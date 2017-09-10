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
Rate limit plug-in.

@author: Daniele Canavese
"""

from cybertop import ActionPlugin

class LimitPlugin(ActionPlugin):
    """
    Translates an IT resource to perform the rate limiting of some packets.
    """
    
    # The fall-back value for the TCP max connections.
    MAX_CONNECTIONS = 20
    # The fall-back value for the TCP rate limit.
    RATE_LIMIT = "100/s"
    
    def configureITResource(self, itResource, hsplSet):
        """
        Configures an IT resource.
        @param itResource: The IT resource to configure.
        @param hsplSet: The HSPL to refine into MSPLs.
        """
        
        protocols = set()
        for i in hsplSet:
            protocol = i.findtext("{%s}traffic-constraints/{%s}type" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
            protocols.add(protocol)    
        
        maxConnections = self.configParser.get("limit", "maxConnections", fallback = self.MAX_CONNECTIONS)
        configuration = self.createFilteringConfiguration(itResource, "drop", "FMR")
        if "TCP" in protocols:
            self.createFilteringRule(configuration, 1, "reject", direction = "inbound", protocol = "TCP", maxConnections = maxConnections)

        count = 1
        for i in hsplSet:
            if i.tag == "{%s}hspl" % self.NAMESPACE_HSPL:
                count += 1
                subjectParts = i.findtext("{%s}subject" % self.NAMESPACE_HSPL).split(":")
                objectParts = i.findtext("{%s}object" % self.NAMESPACE_HSPL).split(":")
                protocol = i.findtext("{%s}traffic-constraints/{%s}type" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
                maxConnections = i.findtext("{%s}traffic-constraints/{%s}max-connections" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
                if maxConnections is None:
                    maxConnections = self.configParser.get("limit", "maxConnections", fallback = self.MAX_CONNECTIONS)
                rateLimit = i.findtext("{%s}traffic-constraints/{%s}rate-limit" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
                if rateLimit is None:
                    rateLimit = self.configParser.get("limit", "rateLimit", fallback = self.RATE_LIMIT)
                if protocol == "TCP":
                    self.createFilteringRule(configuration, count, "accept", direction = "inbound", sourceAddress = objectParts[0],
                                             sourcePort = objectParts[1], destinationAddress = subjectParts[0], destinationPort = subjectParts[1],
                                             protocol = protocol, maxConnections = maxConnections, rateLimit = rateLimit)
                else:
                    self.createFilteringRule(configuration, count, "accept", direction = "inbound", sourceAddress = objectParts[0],
                                             sourcePort = objectParts[1], destinationAddress = subjectParts[0], destinationPort = subjectParts[1],
                                             protocol = protocol)
