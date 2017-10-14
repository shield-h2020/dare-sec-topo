# Copyright 2017 Politecnico di Torino
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from reportlab.platypus import para
"""
HSPL and stuff.

@author: Daniele Canavese
"""

from lxml import etree
from cybertop.util import getHSPLXSDFile
from cybertop.util import getRecipeNamespace
from cybertop.util import getHSPLNamespace
from cybertop.util import getXSINamespace
from cybertop.log import LOG
import re
import copy
from ipaddress import ip_address
from ipaddress import ip_network
import datetime

class HSPLReasoner(object):
    """
    Finds the HSPLs that can be used to mitigate an attack.
    """
    
    def __init__(self, configParser, pluginManager):
        """
        Constructor.
        @param configParser: The configuration parser.
        @param pluginManager: The plug-in manager.
        """
        self.configParser = configParser
        self.pluginManager = pluginManager
        
    def getHSPLs(self, attack, recipe, landscape):
        """
        Retrieve the HSPLs that can be used to mitigate an attack.
        @param attack: The attack to mitigate.
        @param recipe: The recipe to use.
        @param landscape: The landscape.
        @return: The XML HSPL set that can mitigate the attack. It is None if no recipe is available.
        @raise SyntaxError: When the generated XML is not valid.
        """
        if recipe is None:
            return None
        
        schema = etree.XMLSchema(etree.parse(getHSPLXSDFile()))
        
        hsplSet = etree.Element("{%s}hspl-set" % getHSPLNamespace(), nsmap = {None : getHSPLNamespace(), "xsi" : getXSINamespace()})
        
        # Gather some data about the recipe.
        recipeName = recipe.findtext("{%s}name" % getRecipeNamespace())
        recipeAction = recipe.findtext("{%s}action" % getRecipeNamespace())
        recipeType = recipe.findtext("{%s}traffic-constraints/{%s}type" % (getRecipeNamespace(), getRecipeNamespace()))
        recipeMaxConnections = recipe.findtext("{%s}traffic-constraints/{%s}max-connections" % (getRecipeNamespace(), getRecipeNamespace()))
        recipeRateLimit = recipe.findtext("{%s}traffic-constraints/{%s}rate-limit" % (getRecipeNamespace(), getRecipeNamespace()))
        
        # Adds the context.
        context = etree.SubElement(hsplSet, "{%s}context" % getHSPLNamespace())
        etree.SubElement(context, "{%s}severity" % getHSPLNamespace()).text = str(attack.severity)
        etree.SubElement(context, "{%s}type" % getHSPLNamespace()).text = attack.type
        etree.SubElement(context, "{%s}timestamp" % getHSPLNamespace()).text = attack.getTimestamp().isoformat()
        
        # Filters the events.
        events = []
        recipeFilters = recipe.find("{%s}filters" % getRecipeNamespace())
        evaluation = "or"
        if recipeFilters is None:
            events = attack.events
        else:
            if "evaluation" in recipeFilters.attrib.keys():
                evaluation = recipeFilters.attrib["evaluation"]
            for i in attack.events:
                if evaluation == "or":
                    test = False
                else:
                    test = True
                for j in self.pluginManager.getPluginsOfCategory("Filter"):
                    pluginTag = j.details.get("Core", "Tag")
                    filterValues = recipeFilters.findall("{%s}%s" % (getRecipeNamespace(), pluginTag))
                    for k in filterValues:
                        t = j.plugin_object.filter(k.text, i)
                        if evaluation == "or":
                            test = test or t
                        else:
                            test = test and t
                if test:
                    events.append(i)
                
        # Adds an HSPL for each event.
        count = 0
        for i in events:
            count += 1
            hspl = etree.SubElement(hsplSet, "{%s}hspl" % getHSPLNamespace())
            etree.SubElement(hspl, "{%s}name" % getHSPLNamespace()).text = "%s #%d" % (recipeName, count)
            etree.SubElement(hspl, "{%s}subject" % getHSPLNamespace()).text = i.target
            etree.SubElement(hspl, "{%s}action" % getHSPLNamespace()).text = recipeAction
            etree.SubElement(hspl, "{%s}object" % getHSPLNamespace()).text = i.attacker
            trafficConstraints = etree.SubElement(hspl, "{%s}traffic-constraints" % getHSPLNamespace())
            if recipeType is not None:
                eventType = recipeType
            else:
                eventType = i.fields["protocol"]
            etree.SubElement(trafficConstraints, "{%s}type" % getHSPLNamespace()).text = eventType
            if eventType == "TCP" and recipeMaxConnections is not None:
                etree.SubElement(trafficConstraints, "{%s}max-connections" % getHSPLNamespace()).text = recipeMaxConnections
            if recipeRateLimit is not None:
                etree.SubElement(trafficConstraints, "{%s}rate-limit" % getHSPLNamespace()).text = recipeRateLimit
        
        if schema.validate(hsplSet):
            hsplSet = self.__cleanAndMerge(hsplSet)
                
            LOG.debug(etree.tostring(hsplSet, pretty_print = True).decode())
            
            return hsplSet
        else:
            LOG.critical("Invalid HSPL set generated.")
            raise SyntaxError("Invalid HSPL set generated.")

    def __cleanAndMerge(self, hsplSet):
        """
        Polish an HSPL set by removing the duplicate HSPLs and merging them together, if needed. We only work on the objects.
        @param hsplSet: The HSPL set to use.
        @return: The cleaned HSPL set.
        """
        hsplMergingThreshold = int(self.configParser.get("global", "hsplMergingThreshold"))
        hsplMergingMinBits = int(self.configParser.get("global", "hsplMergingMinBits"))
        hsplMergingMaxBits = int(self.configParser.get("global", "hsplMergingMaxBits"))
        
        hsplCount = len(hsplSet.getchildren()) - 1
        if hsplCount == 1:
            LOG.info("%d initial HSPL generated.", hsplCount)
        else:
            LOG.info("%d initial HSPLs generated.", hsplCount)
        
        hspls = []
        
        # Pass 0: extracts the HSPLs.
        for i in hsplSet:
            if i.tag == "{%s}hspl" % getHSPLNamespace():
                hspls.append(i)
        hsplMap = self.__buildMap(hspls)
        
        # Pass 1: removes the included HSPLs.
        includedHSPLs = self.__findInclusions(hspls, hsplMap)
        for i in includedHSPLs:
            hspls.remove(i)
            hsplSet.remove(i)
        if len(includedHSPLs) == 1:
            LOG.debug("%d included HSPL removed.", len(includedHSPLs))
        elif len(includedHSPLs) > 1:
            LOG.debug("%d included HSPLs removed.", len(includedHSPLs))
         
        # Pass 2: merges the IP address using * as the port number.
        mergedHSPLs = set()
        if len(hspls) > hsplMergingThreshold:
            for i in range(0, len(hspls) - 1):
                hspl1 = hspls[i]
                object1 = hspl1.find("{%s}object" % getHSPLNamespace())
                newHSPL = copy.deepcopy(hspl1)
                newObject = newHSPL.find("{%s}object" % getHSPLNamespace())
                m = re.match("(\d+\.\d+\.\d+\.\d+)(:(\d+|\*|any))?", newObject.text)
                if m:
                    newObject.text = "%s:*" % m.group(1)
                for j in range(i + 1, len(hspls)):
                    hspl2 = hspls[j]
                    if hspl2 not in mergedHSPLs and self.__checkIncludedHSPLs(newHSPL, hspl2):
                        object1.text = newObject.text
                        mergedHSPLs.add(hspl2)
        for i in mergedHSPLs:
            hspls.remove(i)
            hsplSet.remove(i)
        if len(mergedHSPLs) == 1:
            LOG.debug("%d HSPL merged using any port.", len(mergedHSPLs))
        elif len(mergedHSPLs) > 1:
            LOG.debug("%d HSPLs merged using any ports.", len(mergedHSPLs))
        
        # Pass 3: merges the HSPLs, if needed.
        mergedHSPLs = set()
        bits = 32 - hsplMergingMinBits
        while len(hspls) - len(mergedHSPLs) > hsplMergingThreshold and bits <= 32 - hsplMergingMaxBits:
            for i in range(0, len(hspls) - 1):
                hspl1 = hspls[i]
                object1 = hspl1.find("{%s}object" % getHSPLNamespace())
                newHSPL = copy.deepcopy(hspl1)
                newObject = newHSPL.find("{%s}object" % getHSPLNamespace())
                m1 = re.match("(\d+\.\d+\.\d+\.\d+(/\d+)?)(:(\d+|\*|any))?", newObject.text)
                if m1:
                    address1 = "%s/%d" % (ip_address((int(ip_network(m1.group(1)).network_address) >> bits) << bits), 32 - bits)
                    port1 = m1.group(4)
                    for j in range(i + 1, len(hspls)):
                        hspl2 = hspls[j]
                        newObject.text = "%s:%s" % (address1, port1)
                        if self.__checkIncludedHSPLs(newHSPL, hspl2):
                            object1.text = newObject.text
                            mergedHSPLs.add(hspl2)
            bits += 1
        for i in mergedHSPLs:
            hspls.remove(i)
            hsplSet.remove(i)
        if len(mergedHSPLs) == 1:
            LOG.debug("%d HSPL merged using subnets.", len(mergedHSPLs))
        elif len(mergedHSPLs) > 1:
            LOG.debug("%d HSPLs merged using subnets.", len(mergedHSPLs))
        
        hsplCount = len(hsplSet.getchildren()) - 1
        if hsplCount == 1:
            LOG.info("%d HSPL remaining.", hsplCount)
        else:
            LOG.info("%d HSPLs remaining.", hsplCount)

        return hsplSet

    def __checkIncludedHSPLs(self, hspl1, hspl2):
        """
        Checks if the first HSPLs includes the second one.
        @param hspl1: The first HSPL.
        @param hspl2: The second HSPL.
        @return: True if the two HSPLs are equivalent or the first HSPL include the second one, False otherwise.
        """
        subject1 = hspl1.findtext("{%s}subject" % getHSPLNamespace())
        subject2 = hspl2.findtext("{%s}subject" % getHSPLNamespace())
        action1 = hspl1.findtext("{%s}action" % getHSPLNamespace())
        action2 = hspl2.findtext("{%s}action" % getHSPLNamespace())
        object1 = hspl1.findtext("{%s}object" % getHSPLNamespace())
        object2 = hspl2.findtext("{%s}object" % getHSPLNamespace())
        trafficConstraints1 = hspl1.find("{%s}traffic-constraints" % getHSPLNamespace())
        trafficConstraints2 = hspl2.find("{%s}traffic-constraints" % getHSPLNamespace())

        m1 = re.match("(\d+\.\d+\.\d+\.\d+(/\d+)?)(:(\d+|\*|any))?", object1)
        m2 = re.match("(\d+\.\d+\.\d+\.\d+(/\d+)?)(:(\d+|\*|any))?", object2)
        objectCheck = False
        if m1 and m2:
            address1 = ip_network(m1.group(1))
            address2 = ip_network(m2.group(1))
            n1 = int(address1.network_address) >> (32 - address1.prefixlen)
            n2 = int(address2.network_address) >> (32 - address1.prefixlen)
            port1 = m1.group(4)
            port2 = m2.group(4)
            if n1 == n2 and (port1 == port2 or port1 == "*" or port1 == "any"):
                objectCheck = True

        if subject1 == subject2 and action1 == action2 and objectCheck and self.__checkEqualXML(trafficConstraints1, trafficConstraints2):
            return True
        
        return False

    def __checkEqualXML(self, tree1, tree2):
        """
        Checks if the two XML tree are the same.
        @param tree1: The first tree.
        @param tree2: The second tree.
        @return: True if the two trees are equivalent, False otherwise.
        """
        if tree1.tag != tree2.tag:
            return False
        if tree1.text != tree2.text:
            return False
        if tree1.tail != tree2.tail:
            return False
        if tree1.attrib != tree2.attrib:
            return False
        if len(tree1) != len(tree2):
            return False
        
        return all(self.__checkEqualXML(c1, c2) for c1, c2 in zip(tree1, tree2))

    def __getHash(self, hspl):
        """
        Retrieves the constant hash of an HSPL.
        @param hspls: The HSPL.
        @return: The constant hash of the HSPL.
        """
        subject = hspl.find("{%s}subject" % getHSPLNamespace())
        action = hspl.find("{%s}action" % getHSPLNamespace())
        trafficConstraints = hspl.find("{%s}traffic-constraints" % getHSPLNamespace())
        h = 1
        h = 37 * h + hash(etree.tostring(subject))
        h = 37 * h + hash(etree.tostring(action))
        h = 37 * h + hash(etree.tostring(trafficConstraints))
        return h
    
    def __getBytes(self, ip):
        """
        Retrieves the four bytes of an IPv4 address.
        @param ip: The ip.
        @return An array of four bytes.
        """
        address = ip_network(ip)
        n = (int(address.network_address) >> (32 - address.prefixlen)) << (32 - address.prefixlen)
        return [(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]

    def __getHSPLObjectBytes(self, hspl):
        """
        Retrieves the four IPv4 bytes of an HSPL object.
        @param hspl: The HSPL.
        @return An array of four bytes or None if the object is not an IPv4.
        """
        xxx = hspl.findtext("{%s}object" % getHSPLNamespace())
        m = re.match("(\d+\.\d+\.\d+\.\d+(/\d+)?)(:(\d+|\*|any))?", xxx)
        if m:
            address = ip_network(m.group(1))
            n = (int(address.network_address) >> (32 - address.prefixlen)) << (32 - address.prefixlen)
            return [(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
        else:
            return None

    def __buildMap(self, hspls):
        """
        Builds the HSPL map.
        @param hspls: The HSPLs.
        @return: The map.
        """
        hsplMap = {}
        # This is a multi-level map where:
        #  + the first key is given by an HSPL hash of subject+action+constraints
        #  + the second key is the first byte of an IPv4 address
        #  + the third key is the second byte of an IPv4 address
        #  + the forth key is the third byte of an IPv4 address
        #  + the fifth key is the forth byte of an IPv4 address
        #  + the values are a list of HSPLs
        for i in hspls:
            key = self.__getHash(i)
            if key not in hsplMap:
                hsplMap[key] = {}
            parts = self.__getHSPLObjectBytes(i)
            if parts is not None:
                mapByte0 = hsplMap[key]
                if parts[0] not in mapByte0:
                    mapByte0[parts[0]] = {}

                mapByte1 = mapByte0[parts[0]]
                if parts[1] not in mapByte1:
                    mapByte1[parts[1]] = {}
                    
                mapByte2 = mapByte1[parts[1]]
                if parts[2] not in mapByte2:
                    mapByte2[parts[2]] = {}

                mapByte3 = mapByte2[parts[2]]
                if parts[3] not in mapByte3:
                    mapByte3[parts[3]] = []
                    
                mapByte3[parts[3]].append(i)
        
        return hsplMap

    def __findInclusions(self, hspls, hsplMap):
        """
        Finds the included HSPLs.
        @param hspls: The HSPLs.
        @param hsplMap: The HSPL map.
        @return: The included HSPLs.
        """
        start = datetime.datetime.now()
        includedHSPLs = set()
        for i in hspls:
            key = self.__getHash(i)
            parts = self.__getHSPLObjectBytes(i)
            if key in hsplMap:
                byte0Map = hsplMap[key]
                if parts[0] in byte0Map:
                    byte1Map = byte0Map[parts[0]]
                    if parts[1] in byte1Map:
                        byte2Map = byte1Map[parts[1]]
                        if parts[2] in byte2Map:
                            byte3Map = byte2Map[parts[2]]
                            if parts[3] in byte3Map:
                                l = byte3Map[parts[3]]
                                for j in l:
                                    if i != j and i not in includedHSPLs and j not in includedHSPLs and self.__checkIncludedHSPLs(i, j):
                                        includedHSPLs.add(j)
        stop = datetime.datetime.now()
        print("TIME:", stop - start)
        return includedHSPLs
