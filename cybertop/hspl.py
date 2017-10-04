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
from cybertop.util import get_hspl_xsd_path
from cybertop.log import LOG

class HSPLReasoner(object):
    """
    Finds the HSPLs that can be used to mitigate an attack.
    """

    # The recipe namespace.
    NAMESPACE_RECIPE = "http://security.polito.it/shield/recipe"
    # The HSPL namespace.
    NAMESPACE_HSPL = "http://security.polito.it/shield/hspl"
    # The XSI namespace.
    NAMESPACE_XSI = "http://www.w3.org/2001/XMLSchema-instance"
    
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
        
        schema = etree.XMLSchema(etree.parse(get_hspl_xsd_path()))
        
        hsplSet = etree.Element("{%s}hspl-set" % self.NAMESPACE_HSPL, nsmap = {None : self.NAMESPACE_HSPL, "xsi" : self.NAMESPACE_XSI})
        
        # Gather some data about the recipe.
        recipeName = recipe.findtext("{%s}name" % self.NAMESPACE_RECIPE)
        recipeAction = recipe.findtext("{%s}action" % self.NAMESPACE_RECIPE)
        recipeType = recipe.findtext("{%s}traffic-constraints/{%s}type" % (self.NAMESPACE_RECIPE, self.NAMESPACE_RECIPE))
        recipeMaxConnections = recipe.findtext("{%s}traffic-constraints/{%s}max-connections" % (self.NAMESPACE_RECIPE, self.NAMESPACE_RECIPE))
        recipeRateLimit = recipe.findtext("{%s}traffic-constraints/{%s}rate-limit" % (self.NAMESPACE_RECIPE, self.NAMESPACE_RECIPE))
        
        # Adds the context.
        context = etree.SubElement(hsplSet, "{%s}context" % self.NAMESPACE_HSPL)
        etree.SubElement(context, "{%s}severity" % self.NAMESPACE_HSPL).text = str(attack.severity)
        etree.SubElement(context, "{%s}type" % self.NAMESPACE_HSPL).text = attack.type
        etree.SubElement(context, "{%s}timestamp" % self.NAMESPACE_HSPL).text = attack.getTimestamp().isoformat()
        
        # Adds an HSPL for each event.
        count = 0
        for i in attack.events:
            count += 1
            hspl = etree.SubElement(hsplSet, "{%s}hspl" % self.NAMESPACE_HSPL)
            etree.SubElement(hspl, "{%s}name" % self.NAMESPACE_HSPL).text = "%s #%d" % (recipeName, count)
            etree.SubElement(hspl, "{%s}subject" % self.NAMESPACE_HSPL).text = "%s:%d" % (str(i.destinationAddress), i.destinationPort)
            etree.SubElement(hspl, "{%s}action" % self.NAMESPACE_HSPL).text = recipeAction
            etree.SubElement(hspl, "{%s}object" % self.NAMESPACE_HSPL).text = "%s:%d" % (str(i.sourceAddress), i.sourcePort)
            if recipeType is not None or recipeMaxConnections is not None or recipeRateLimit is not None:
                trafficConstraints = etree.SubElement(hspl, "{%s}traffic-constraints" % self.NAMESPACE_HSPL)
                if recipeType is not None:
                    etree.SubElement(trafficConstraints, "{%s}type" % self.NAMESPACE_HSPL).text = recipeType
                if recipeMaxConnections is not None:
                    etree.SubElement(trafficConstraints, "{%s}max-connections" % self.NAMESPACE_HSPL).text = recipeMaxConnections
                if recipeRateLimit is not None:
                    etree.SubElement(trafficConstraints, "{%s}rate-limit" % self.NAMESPACE_HSPL).text = recipeRateLimit
        
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
