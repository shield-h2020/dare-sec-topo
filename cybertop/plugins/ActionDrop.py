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

from cybertop.plugins import ActionPlugin
from cybertop.util import getHSPLNamespace

class ActionDrop(ActionPlugin):
    """
    Translates an IT resource to perform the dropping of some packets.
    """
    
    def configureITResource(self, itResource, hsplSet):
        """
        Configures an IT resource.
        @param itResource: The IT resource to configure.
        @param hsplSet: The HSPL to refine into MSPLs.
        """
        
        configuration = self.createFilteringConfiguration(itResource, "accept", "FMR")

        count = 0
        for i in hsplSet:
            if i.tag == "{%s}hspl" % getHSPLNamespace():
                subjectParts = i.findtext("{%s}subject" % getHSPLNamespace()).split(":")
                objectParts = i.findtext("{%s}object" % getHSPLNamespace()).split(":")
                protocol = i.findtext("{%s}traffic-constraints/{%s}type" % (getHSPLNamespace(), getHSPLNamespace()))
                if protocol == "TCP+UDP":
                    count += 1
                    self.createFilteringRule(configuration, count, "drop", direction = "inbound", sourceAddress = objectParts[0],
                        sourcePort = objectParts[1], destinationAddress = subjectParts[0], destinationPort = subjectParts[1],
                        protocol = "TCP")
                    count += 1
                    self.createFilteringRule(configuration, count, "drop", direction = "inbound", sourceAddress = objectParts[0],
                        sourcePort = objectParts[1], destinationAddress = subjectParts[0], destinationPort = subjectParts[1],
                        protocol = "UDP")
                else:
                    count += 1
                    self.createFilteringRule(configuration, count, "drop", direction = "inbound", sourceAddress = objectParts[0],
                        sourcePort = objectParts[1], destinationAddress = subjectParts[0], destinationPort = subjectParts[1],
                        protocol = protocol)
