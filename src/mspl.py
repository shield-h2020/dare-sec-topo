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
MSPL and stuff.

@author: Daniele Canavese
"""

import logging
from lxml import etree
import re
import random

class MSPLReasoner(object):
    """
    Finds the MSPLs that can be used to mitigate an attack.
    """

    # The HSPL namespace.
    NAMESPACE_HSPL = "http://security.polito.it/shield/hspl"
    # The HSPL namespace.
    NAMESPACE_MSPL = "http://security.polito.it/shield/mspl"
    # The XSI namespace.
    NAMESPACE_XSI = "http://www.w3.org/2001/XMLSchema-instance"
    
    def __init__(self, configParser, pluginManager):
        """
        Constructor.
        @param configParser: The configuration parser.
        @param pluginManager: The plug-in manager.
        """
        self.logger = logging.getLogger("MSPL-reasoner")
        self.configParser = configParser
        self.pluginManager = pluginManager
        self.logger.debug("MSPLs reasoner initialized.")
    
    def getMSPLs(self, hsplSet, landscape):
        """
        Retrieve the HSPLs that can be used to mitigate an attack.
        @param hsplSet: The HSPL set to use.
        @param landscape: The landscape.
        @return: The XML MSPL set that can mitigate the attack. It is None if no HSPL is available.
        @raise SyntaxError: When the generated XML is not valid.
        """
        if hsplSet is None:
            return None
        
        hsplSchema = self.configParser.get("global", "msplSchema")
        schema = etree.XMLSchema(etree.parse(hsplSchema))
        
        msplSet = etree.Element("{%s}mspl-set" % self.NAMESPACE_MSPL, nsmap = {None : self.NAMESPACE_MSPL, "xsi" : self.NAMESPACE_XSI})
                  
        # Gather some data about the recipe.
        msplSeverity = hsplSet.findtext("{%s}context/{%s}severity" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        msplType = hsplSet.findtext("{%s}context/{%s}type" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        msplTimestamp = hsplSet.findtext("{%s}context/{%s}timestamp" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        
        # Adds the context.
        context = etree.SubElement(msplSet, "{%s}context" % self.NAMESPACE_MSPL)
        etree.SubElement(context, "{%s}severity" % self.NAMESPACE_MSPL).text = msplSeverity
        etree.SubElement(context, "{%s}type" % self.NAMESPACE_MSPL).text = msplType
        etree.SubElement(context, "{%s}timestamp" % self.NAMESPACE_MSPL).text = msplTimestamp
        
        # Finds a plug-in that can create a configured IT resource.
        [plugin, identifier] = self.__findLocation(hsplSet, landscape)
        plugin.plugin_object.setup(self.configParser)
        
        # Creates the IT resource.
        itResource = etree.SubElement(msplSet, "{%s}it-resource" % self.NAMESPACE_MSPL, {"id" : identifier})
        
        # Calls the plug-in to configure the IT resource.
        plugin.plugin_object.configureITResource(itResource, hsplSet)
        
        if schema.validate(msplSet):
            msplCount = len(msplSet.getchildren()) - 1
            if msplCount == 1:
                self.logger.info("%d MSPL generated.", msplCount)
            else:
                self.logger.info("%d MSPLs generated.", msplCount)
            return msplSet
        else:
            self.logger.critical("Invalid MSPL set generated.")
            raise SyntaxError("Invalid MSPL set generated.")
    
    def __findLocation(self, hsplSet, landscape):
        """
        Finds a suitable plug-in and location for the HSPL refinement.
        @param hsplSet: The HSPL set to use.
        @param landscape: The landscape.
        @return: The plug-in and IT resource identifier, or [None, None] if nobody is useful. What a shame.
        """
        plugins = set()
        identifiers = set()
        hsplAction = hsplSet.findtext("{%s}hspl/{%s}action" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        for i in self.pluginManager.getPluginsOfCategory("Action"):
            pluginAction = i.details.get("Core", "Action")
            pluginCapabilities = set(re.split("\s*,\s*", i.details.get("Core", "Capabilities")))
            if hsplAction == pluginAction:
                for identifier, capabilities in landscape.items():
                    if pluginCapabilities.issubset(capabilities):
                        plugins.add(i)
                        identifiers.add(identifier)
        
        # Picks a random plug-in.
        if len(plugins) == 0:
            plugin = None
        else:
            plugin = random.sample(plugins, 1)[0]
        
        # Picks a random identifier.
        if len(identifiers) == 0:
            identifier = None
        else:
            identifier = random.sample(identifiers, 1)[0]
            
        return [plugin, identifier]
