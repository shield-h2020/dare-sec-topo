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
from ipaddress import ip_address
from ipaddress import ip_network

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
        recipeObjectAnyPort = recipe.findtext("{%s}object-constraints/{%s}any-port" % (getRecipeNamespace(), getRecipeNamespace()))
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
            print("EVENTS", len(events))
            for i in attack.events:
                if evaluation == "or":
                    test = False
                else:
                    test = True
                print("START", test)
                for j in self.pluginManager.getPluginsOfCategory("Filter"):
                    pluginTag = j.details.get("Core", "Tag")
                    filterValues = recipeFilters.findall("{%s}%s" % (getRecipeNamespace(), pluginTag))
                    for k in filterValues:
                        t = j.plugin_object.filter(k.text, i)
                        if evaluation == "or":
                            test = test or t
                        else:
                            test = test and t
                        print("FILTER", pluginTag, k.text, test)
                print("FINAL", test)
                if not test:
                    events.append(i)
                print("EVENTS", len(events))
                
        # Adds an HSPL for each event.
        count = 0
        for i in events:
            count += 1
            hspl = etree.SubElement(hsplSet, "{%s}hspl" % getHSPLNamespace())
            etree.SubElement(hspl, "{%s}name" % getHSPLNamespace()).text = "%s #%d" % (recipeName, count)
            etree.SubElement(hspl, "{%s}subject" % getHSPLNamespace()).text = i.target
            etree.SubElement(hspl, "{%s}action" % getHSPLNamespace()).text = recipeAction
            attacker = i.attacker
            if recipeObjectAnyPort is not None:
                m = re.match("(\d+\.\d+\.\d+\.\d+(/\d+)?)(:(\d+|\*|any))?", i.attacker)
                if m:
                    address = m.group(1)
                    attacker = "%s:*" % address
            etree.SubElement(hspl, "{%s}object" % getHSPLNamespace()).text = attacker
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
        hsplMergeInclusions = int(self.configParser.getboolean("global", "hsplMergeInclusions"))
        hsplMergeWithAnyPorts = int(self.configParser.getboolean("global", "hsplMergeWithAnyPorts"))
        hsplMergeWithSubnets = int(self.configParser.getboolean("global", "hsplMergeWithSubnets"))
        
        if not hsplMergeInclusions and not hsplMergeWithAnyPorts and not hsplMergeWithSubnets:
            return hsplSet

        hsplCount = len(hsplSet.getchildren()) - 1
        if hsplCount == 1:
            LOG.info("%d initial HSPL generated.", hsplCount)
        else:
            LOG.info("%d initial HSPLs generated.", hsplCount)
                        
        # Pass 0: create the map.
        hsplMap = HSPLMap()
        for i in hsplSet:
            if i.tag == "{%s}hspl" % getHSPLNamespace():
                hsplMap.add(i)
        
        # Pass 1: removes the included HSPLs.
        if hsplMergeInclusions:
            includedHSPLs = self.__mergeInclusions(hsplSet, hsplMap)
            if includedHSPLs > 1:
                LOG.debug("%d included HSPLs removed.", includedHSPLs)
            else:
                LOG.debug("%d included HSPL removed.", includedHSPLs)
         
        # Pass 2: merges the IP address using * as the port number.
        if hsplMergeWithAnyPorts:
            mergedHSPLs = self.__mergeWithAnyPorts(hsplSet, hsplMap)
            if mergedHSPLs > 1:
                LOG.debug("%d HSPLs merged using any ports.", mergedHSPLs)
            else:
                LOG.debug("%d HSPL merged using any port.", mergedHSPLs)
         
        # Pass 3: merges the HSPLs, if needed.
        if hsplMergeWithSubnets:
            mergedHSPLs = self.__mergeWithSubnets(hsplSet, hsplMap)
            if mergedHSPLs > 1:
                LOG.debug("%d HSPLs merged using subnets.", mergedHSPLs)
            else:
                LOG.debug("%d HSPL merged using subnets.", mergedHSPLs)
        
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
    
    def __mergeInclusions(self, hsplSet, hsplMap):
        """
        Merges the included HSPLs.
        @param hsplSet: The HSPL set to edit.
        @param hsplMap: The HSPL map to use.
        @return: The number of included HSPLs removed.
        """
        hspls = set()
        
        for i in hsplMap.getHSPLs():
            if i not in hspls:
                inclusions = hsplMap.find(i)
                inclusions.remove(i)
                hspls.update(inclusions)

        for i in hspls:
            hsplMap.remove(i)
            hsplSet.remove(i)

        return len(hspls)

    def __mergeWithAnyPorts(self, hsplSet, hsplMap):
        """
        Merges together several HSPLs by using * as a port.
        @param hsplSet: The HSPL set to edit.
        @return: The number of merged HSPLs removed.
        """
        hsplMergingThreshold = int(self.configParser.get("global", "hsplMergingThreshold"))
        
        if len(hsplSet) <= hsplMergingThreshold:
            return 0
        
        hspls = set()
        mergedHSPLs = []

        for i in hsplMap.getHSPLs():
            if i not in hspls:
                inclusions = hsplMap.find(i, None, True)
                if len(inclusions) > 1:
                    mergedHSPLs.append(inclusions)
                    hspls.update(inclusions)
                
        for i in mergedHSPLs:
            s = set(i)
            first = s.pop()
            firstObject = first.find("{%s}object" % getHSPLNamespace())
            m = re.match("(\d+\.\d+\.\d+\.\d+(/\d+)?)(:(\d+|\*|any))?", firstObject.text)
            address = m.group(1)
            firstObject.text = "%s:*" % address
            for j in s:
                hsplMap.remove(j)
                if j in hsplSet:
                    hsplSet.remove(j)

        return len(hspls) - len(mergedHSPLs)

    def __mergeWithSubnets(self, hsplSet, hsplMap):
        """
        Merges together several HSPLs by using subnets.
        @param hsplSet: The HSPL set to edit.
        @return: The number of merged HSPLs removed.
        """
        hsplMergingThreshold = int(self.configParser.get("global", "hsplMergingThreshold"))
        hsplMergingMinBits = int(self.configParser.get("global", "hsplMergingMinBits"))
        hsplMergingMaxBits = int(self.configParser.get("global", "hsplMergingMaxBits"))
        bits = hsplMergingMinBits
        
        merged = set()
        while len(hsplMap.getHSPLs()) > hsplMergingThreshold and bits >= hsplMergingMaxBits:
            hspls = set()
            mergedHSPLs = []
            
            for i in hsplMap.getHSPLs():
                if i not in hspls:
                    inclusions = hsplMap.find(i, bits, True)
                    if len(inclusions) > 1:
                        mergedHSPLs.append(inclusions)
                        hspls.update(inclusions)
                        
            for i in mergedHSPLs:
                s = set(i)
                first = s.pop()
                firstObject = first.find("{%s}object" % getHSPLNamespace())
                m = re.match("((\d+\.\d+\.\d+\.\d+)(/\d+)?)(:(\d+|\*|any))?", firstObject.text)
                address = ip_address(m.group(2))
                number = int(address)
                n = (number >> (32 - bits)) << (32 - bits)
                firstObject.text = "%s/%d:*" % (ip_address(n), bits)
                for j in s:
                    hsplMap.remove(j)
                    hsplSet.remove(j)
                merged.update(s)
                
            bits -= 1
        
        return len(merged)

class HSPLMap:
    """
    An HSPL map.
    So, the internal map is basically a multi-level dictionary:
     + the keys are the HSPL constant hash, the object IPv4 prefix length, the object IPv4 network address and the port
     + the values are a list of HSPLs
    This dictionary maps an HSPL to a set of HSPLs that are included.
    Note that a single HSPL can appear in several different buckets.
    Note also that single IPv4 addresses are treated as networks with a prefix length of 32.
    """
    
    def __init__(self):
        """
        Creates an empty map.
        """
        self.__map = {}
        self.__hspls = set()

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

    def add(self, hspl):
        """
        Adds a new HSPL to the map.
        @param hspl: The HSPL to add.
        """
        hsplObject = hspl.findtext("{%s}object" % getHSPLNamespace())
        m = re.match("(\d+\.\d+\.\d+\.\d+(/\d+)?)(:(\d+|\*|any))?", hsplObject)
        
        if m:
            key = self.__getHash(hspl)
            address = ip_network(m.group(1))
            port = m.group(4)
            prefixLength = address.prefixlen
            number = int(address.network_address)
            if key not in self.__map:
                self.__map[key] = {}
            mapPrefixes = self.__map[key]
            for i in range(0, prefixLength + 1):
                if i not in mapPrefixes:
                    mapPrefixes[i] = {}
                mapAddresses = mapPrefixes[i]
                n = (number >> (32 - i)) << (32 - i)
                if n not in mapAddresses:
                    mapAddresses[n] = {}
                mapPort = mapAddresses[n]
                if "*" not in mapPort:
                    mapPort["*"] = set()
                mapPort["*"].add(hspl)
                if port not in mapPort:
                    mapPort[port] = set()
                mapPort[port].add(hspl)
            
                self.__hspls.add(hspl)

    def find(self, hspl, forcePrefixLength = None, forceAnyPort = False):
        """
        Finds all the inclusions of a HSPLs.
        @param hspl: The HSPL to search for the inclusions.
        @param forcePrefixLength: The prefix length to use for the search or None to use the HSPL prefix length. 
        @param forceAnyPort: A value stating if we want to force an any port address or keep the original value.
        @return: The set of HSPLs included by the passed HSPL.
        """
        inclusions = set()
        
        hsplObject = hspl.findtext("{%s}object" % getHSPLNamespace())
        m = re.match("(\d+\.\d+\.\d+\.\d+(/\d+)?)(:(\d+|\*|any))?", hsplObject)
        
        if m:
            key = self.__getHash(hspl)
            address = ip_network(m.group(1))
            port = m.group(4)
            if port == "any" or forceAnyPort:
                port = "*"
            if forcePrefixLength is not None:
                prefixLength = forcePrefixLength
            else:
                prefixLength = address.prefixlen
            number = int(address.network_address)
            if key in self.__map:
                mapPrefixes = self.__map[key]
                mapAddresses = mapPrefixes[prefixLength]
                n = (number >> (32 - prefixLength)) << (32 - prefixLength)
                if n in mapAddresses:
                    mapPort = mapAddresses[n]
                    if port in mapPort:
                        inclusions.update(mapPort[port])
            
        return inclusions
    
    def remove(self, hspl):
        """
        Removes an HSPL from the map.
        @param hspl: The HSPL to remove.
        """

        hsplObject = hspl.findtext("{%s}object" % getHSPLNamespace())
        m = re.match("(\d+\.\d+\.\d+\.\d+(/\d+)?)(:(\d+|\*|any))?", hsplObject)

        if m:
            key = self.__getHash(hspl)
            address = ip_network(m.group(1))
            port = m.group(4)
            if port == "any":
                port = "*"
            prefixLength = address.prefixlen
            number = int(address.network_address)
            mapPrefixes = self.__map[key]
            for i in range(0, prefixLength + 1):
                if i in mapPrefixes:
                    mapAddresses = mapPrefixes[i]
                    n = (number >> (32 - i)) << (32 - i)
                    if n in mapAddresses:
                        mapPort = mapAddresses[n]
                        if port in mapPort:
                            mapPort[port].remove(hspl)
                        if port != "*" and "*" in mapPort:
                            mapPort["*"].remove(hspl)
            
            if hspl in self.__hspls:
                self.__hspls.remove(hspl)
            
    def getHSPLs(self):
        """
        Retrieves the set of all the HSPLs inserted.
        @return: All the inserted HSPLs.
        """
        return self.__hspls
