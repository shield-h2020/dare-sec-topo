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
Plug-ins.

@author: Daniele Canavese
"""

from yapsy.PluginManager import IPlugin
from lxml import etree

class ActionPlugin(IPlugin):
    """
    A plug-in for refining an action.
    """
    
    # The HSPL namespace.
    NAMESPACE_HSPL = "http://security.polito.it/shield/hspl"
    # The HSPL namespace.
    NAMESPACE_MSPL = "http://security.polito.it/shield/mspl"
    # The XSI namespace.
    NAMESPACE_XSI = "http://www.w3.org/2001/XMLSchema-instance"
    
    def setup(self, configParser):
        """
        Initializes the plug-in. Always called after the construction.
        @param configParser: The configuration parser.
        """
        self.configParser = configParser

    def configureITResource(self, itResource, hsplSet):
        """
        Configures an IT resource.
        @param itResource: The IT resource to configure.
        @param hsplSet: The HSPL to refine into MSPLs.
        """
        raise NotImplementedError()
    
    def createFilteringConfiguration(self, itResource, defaultAction, resolutionStrategy):
        """
        Creates a filtering configuration.
        @param itResource: The IT resource to configure.
        @param defaultAction: The default action.
        @param resolutionStrategy: The resolution strategy.
        @return: The filtering configuration.
        """
        configuration = etree.SubElement(itResource, "{%s}configuration" % self.NAMESPACE_MSPL)
        configuration.attrib["{{{pre}}}type".format(pre = self.NAMESPACE_XSI)] = "filtering-configuration"
        etree.SubElement(configuration, "{%s}default-action" % self.NAMESPACE_MSPL).text = defaultAction
        etree.SubElement(configuration, "{%s}resolution-strategy" % self.NAMESPACE_MSPL).text = resolutionStrategy
        
        return configuration
    
    def createFilteringRule(self, configuration, priority, action, **conditions):
        """
        Creates a filtering rule.
        @param configuration: The configuration to edit.
        @param priority: The rule priority.
        @param action: The rule action.
        @param conditions: The condition parameters. They can be "direction", "protocol", "sourceAddress", "sourcePort",
            "destinationAddress", "destinationPort", "interface", "maxConnections" and "rateLimit".
        @return: The filtering rule.
        """
        rule = etree.SubElement(configuration, "{%s}rule" % self.NAMESPACE_MSPL)
        etree.SubElement(rule, "{%s}priority" % self.NAMESPACE_MSPL).text = str(priority)
        etree.SubElement(rule, "{%s}action" % self.NAMESPACE_MSPL).text = action
        if len(conditions) > 0:
            condition = etree.SubElement(rule, "{%s}condition" % self.NAMESPACE_MSPL)
            if ("direction" in conditions or "sourceAddress" in conditions or "sourcePort" in conditions or "destinationAddress" in conditions or
                "destinationPort" in conditions or "interface" in conditions or "protocol" in conditions):
                packetFilterCondition = etree.SubElement(condition, "{%s}packet-filter-condition" % self.NAMESPACE_MSPL)
                if "direction" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}direction" % self.NAMESPACE_MSPL).text = conditions["direction"]
                if "sourceAddress" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}source-address" % self.NAMESPACE_MSPL).text = conditions["sourceAddress"]
                if "sourcePort" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}source-port" % self.NAMESPACE_MSPL).text = str(conditions["sourcePort"])
                if "destinationAddress" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}destination-address" % self.NAMESPACE_MSPL).text = conditions["destinationAddress"]
                if "destinationPort" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}destination-port" % self.NAMESPACE_MSPL).text = str(conditions["destinationPort"])
                if "interface" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}interface" % self.NAMESPACE_MSPL).text = conditions["interface"]
                if "protocol" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}protocol" % self.NAMESPACE_MSPL).text = conditions["protocol"]
            if "url" in conditions or "method" in conditions:
                applicationLayerCondition = etree.SubElement(condition, "{%s}application-layer-condition" % self.NAMESPACE_MSPL)
                if "url" in conditions:
                    etree.SubElement(applicationLayerCondition, "{%s}url" % self.NAMESPACE_MSPL).text = conditions["url"]
                if "method" in conditions:
                    etree.SubElement(applicationLayerCondition, "{%s}method" % self.NAMESPACE_MSPL).text = conditions["method"]
            if "state" in conditions:
                statefulCondition = etree.SubElement(condition, "{%s}stateful-condition" % self.NAMESPACE_MSPL)
                if "state" in conditions:
                    etree.SubElement(statefulCondition, "{%s}state" % self.NAMESPACE_MSPL).text = conditions["state"]
            if "maxConnections" in conditions or "rateLimit" in conditions:
                trafficFlowCondition = etree.SubElement(condition, "{%s}traffic-flow-condition" % self.NAMESPACE_MSPL)
                if "maxConnections" in conditions:
                    etree.SubElement(trafficFlowCondition, "{%s}max-connections" % self.NAMESPACE_MSPL).text = str(conditions["maxConnections"])
                if "rateLimit" in conditions:
                    etree.SubElement(trafficFlowCondition, "{%s}rate-limit" % self.NAMESPACE_MSPL).text = conditions["rateLimit"]
        
        return rule
