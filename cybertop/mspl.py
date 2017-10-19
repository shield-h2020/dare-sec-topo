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

from lxml import etree
import re
import random
from cybertop.util import getMSPLXSDFile
from cybertop.util import getHSPLNamespace
from cybertop.util import getMSPLNamespace
from cybertop.util import getXSINamespace
from cybertop.log import LOG

class MSPLReasoner(object):
    """
    Finds the MSPLs that can be used to mitigate an attack.
    """
    
    def __init__(self, configParser, pluginManager):
        """
        Constructor.
        @param configParser: The configuration parser.
        @param pluginManager: The plug-in manager.
        """
        self.configParser = configParser
        self.pluginManager = pluginManager
    
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
        
        schema = etree.XMLSchema(etree.parse(getMSPLXSDFile()))
        
        msplSet = etree.Element("{%s}mspl-set" % getMSPLNamespace(), nsmap = {None : getMSPLNamespace(), "xsi" : getXSINamespace()})
            
        # Gather some data about the recipe.
        msplSeverity = hsplSet.findtext("{%s}context/{%s}severity" % (getHSPLNamespace(), getHSPLNamespace()))
        msplType = hsplSet.findtext("{%s}context/{%s}type" % (getHSPLNamespace(), getHSPLNamespace()))
        msplTimestamp = hsplSet.findtext("{%s}context/{%s}timestamp" % (getHSPLNamespace(), getHSPLNamespace()))
        
        # Adds the context.
        context = etree.SubElement(msplSet, "{%s}context" % getMSPLNamespace())
        etree.SubElement(context, "{%s}severity" % getMSPLNamespace()).text = msplSeverity
        etree.SubElement(context, "{%s}type" % getMSPLNamespace()).text = msplType
        etree.SubElement(context, "{%s}timestamp" % getMSPLNamespace()).text = msplTimestamp
        
        # Finds a plug-in that can create a configured IT resource.
        [plugin, identifier] = self.__findLocation(hsplSet, landscape)
        plugin.plugin_object.setup(self.configParser)
        
        # Creates the IT resource.
        itResource = etree.SubElement(msplSet, "{%s}it-resource" % getMSPLNamespace(), {"id" : identifier})
        
        # Calls the plug-in to configure the IT resource.
        plugin.plugin_object.configureITResource(itResource, hsplSet)
        
        if schema.validate(msplSet):
            msplCount = len(msplSet.getchildren()) - 1
            if msplCount == 1:
                LOG.info("%d MSPL generated.", msplCount)
            else:
                LOG.info("%d MSPLs generated.", msplCount)

            LOG.debug(etree.tostring(msplSet, pretty_print = True).decode())

            return msplSet
        else:
            LOG.critical("Invalid MSPL set generated.")
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
        hsplAction = hsplSet.findtext("{%s}hspl/{%s}action" % (getHSPLNamespace(), getHSPLNamespace()))
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
