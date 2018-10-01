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
from cybertop.util import getMSPLNamespace
from cybertop.util import getXSINamespace

class ParserPlugin(IPlugin):
    """
    A plug-in for parsing an attack event.
    """

    def setup(self, configParser):
        """
        Initializes the plug-in. Always called after the construction.
        @param configParser: The configuration parser.
        """
        self.configParser = configParser

    def parse(self, fileName, count, line):
        """
        Parses an event line.
        @param fileName: The current file name or None if this is a list.
        @param count: The current line count.
        @param line: The line to parse.
        @return: The attack event or None if this line should be silently ignored.
        @raise IOError: if the line contains something invalid.
        """
        raise NotImplementedError()

class FilterPlugin(IPlugin):
    """
    A plug-in for filtering an attack event.
    """

    def setup(self, configParser):
        """
        Initializes the plug-in. Always called after the construction.
        @param configParser: The configuration parser.
        """
        self.configParser = configParser

    def filter(self, value, attackEvent):
        """
        Filters an attack event.
        @param value: The optional value for the filter.
        @param attackEvent: The attack event to analyze.
        @return: True if the event must be accepted, False if the event must be discarded.
        """
        raise NotImplementedError()

class ActionPlugin(IPlugin):
    """
    A plug-in for refining an action.
    """
    
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
        configuration = etree.SubElement(itResource, "{%s}configuration" % getMSPLNamespace())
        configuration.attrib["{{{pre}}}type".format(pre = getXSINamespace())] = "filtering-configuration"
        etree.SubElement(configuration, "{%s}default-action" % getMSPLNamespace()).text = defaultAction
        etree.SubElement(configuration, "{%s}resolution-strategy" % getMSPLNamespace()).text = resolutionStrategy
        
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
        rule = etree.SubElement(configuration, "{%s}rule" % getMSPLNamespace())
        etree.SubElement(rule, "{%s}priority" % getMSPLNamespace()).text = str(priority)
        etree.SubElement(rule, "{%s}action" % getMSPLNamespace()).text = action
        if len(conditions) > 0:
            condition = etree.SubElement(rule, "{%s}condition" % getMSPLNamespace())
            if ("direction" in conditions or "sourceAddress" in conditions or "sourcePort" in conditions or "destinationAddress" in conditions or
                "destinationPort" in conditions or "interface" in conditions or "protocol" in conditions):
                packetFilterCondition = etree.SubElement(condition, "{%s}packet-filter-condition" % getMSPLNamespace())
                if "direction" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}direction" % getMSPLNamespace()).text = conditions["direction"]
                if "sourceAddress" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}source-address" % getMSPLNamespace()).text = conditions["sourceAddress"]
                if "sourcePort" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}source-port" % getMSPLNamespace()).text = str(conditions["sourcePort"])
                if "destinationAddress" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}destination-address" % getMSPLNamespace()).text = conditions["destinationAddress"]
                if "destinationPort" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}destination-port" % getMSPLNamespace()).text = str(conditions["destinationPort"])
                if "interface" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}interface" % getMSPLNamespace()).text = conditions["interface"]
                if "protocol" in conditions:
                    etree.SubElement(packetFilterCondition, "{%s}protocol" % getMSPLNamespace()).text = conditions["protocol"]
            if "url" in conditions or "method" in conditions:
                applicationLayerCondition = etree.SubElement(condition, "{%s}application-layer-condition" % getMSPLNamespace())
                if "url" in conditions:
                    etree.SubElement(applicationLayerCondition, "{%s}url" % getMSPLNamespace()).text = conditions["url"]
                if "method" in conditions:
                    etree.SubElement(applicationLayerCondition, "{%s}method" % getMSPLNamespace()).text = conditions["method"]
            if "state" in conditions:
                statefulCondition = etree.SubElement(condition, "{%s}stateful-condition" % getMSPLNamespace())
                if "state" in conditions:
                    etree.SubElement(statefulCondition, "{%s}state" % getMSPLNamespace()).text = conditions["state"]
            if "maxConnections" in conditions or "rateLimit" in conditions:
                trafficFlowCondition = etree.SubElement(condition, "{%s}traffic-flow-condition" % getMSPLNamespace())
                if "maxConnections" in conditions:
                    etree.SubElement(trafficFlowCondition, "{%s}max-connections" % getMSPLNamespace()).text = str(conditions["maxConnections"])
                if "rateLimit" in conditions:
                    etree.SubElement(trafficFlowCondition, "{%s}rate-limit" % getMSPLNamespace()).text = conditions["rateLimit"]
        
        return rule
