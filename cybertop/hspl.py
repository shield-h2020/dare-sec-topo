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
        
        # Adds an HSPL for each event.
        count = 0
        for i in attack.events:
            count += 1
            hspl = etree.SubElement(hsplSet, "{%s}hspl" % getHSPLNamespace())
            etree.SubElement(hspl, "{%s}name" % getHSPLNamespace()).text = "%s #%d" % (recipeName, count)
            etree.SubElement(hspl, "{%s}subject" % getHSPLNamespace()).text = i.attacker
            etree.SubElement(hspl, "{%s}action" % getHSPLNamespace()).text = recipeAction
            etree.SubElement(hspl, "{%s}object" % getHSPLNamespace()).text = i.target
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
            hsplCount = len(hsplSet.getchildren())
            if hsplCount == 1:
                LOG.info("%d HSPL generated.", hsplCount)
            else:
                LOG.info("%d HSPLs generated.", hsplCount)
            
            LOG.debug(etree.tostring(hsplSet, pretty_print = True).decode())
            
            return hsplSet
        
        else:
            LOG.critical("Invalid HSPL set generated.")
            raise SyntaxError("Invalid HSPL set generated.")
