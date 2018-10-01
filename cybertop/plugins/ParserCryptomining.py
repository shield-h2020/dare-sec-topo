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
Cryptomining attack events parser plug-in.

@author: Daniele Canavese
"""

from cybertop.plugins import ParserPlugin
from cybertop.attacks import AttackEvent
import re
from cybertop.log import LOG
from dateutil import parser
import ipaddress

class ParserCryptomining(ParserPlugin):
    """
    Parses a Cryptomining attack event.
    """
    
    def parse(self, fileName, count, line):
        """
        Parses an event line.
        @param fileName: The current file name or None if this is a list.
        @param count: The current line count.
        @param line: The line to parse.
        @return: The attack event or None if this line should be silently ignored.
        @raise IOError: if the line contains something invalid.
        """
        
        if re.match("\s*#.*", line):
            return None
        
        parts = re.split("\s*,\s*|\s+", line.rstrip())
        
        if parts == [""]:
            return None
        
        try:
            timestamp = parser.parse("%s %s" % (parts[0], parts[1]))
            sourceAddress = ipaddress.ip_address(parts[9])
            destinationAddress = ipaddress.ip_address(parts[10])
            sourcePort = int(parts[11])
            destinationPort = int(parts[12])
            protocol = parts[13]
            inputPackets = int(parts[14])
            inputBytes = int(parts[15])
            outputPackets = int(parts[16])
            outputBytes = int(parts[17])
            
            attackEvent = AttackEvent(timestamp, "%s:%d" % (sourceAddress, sourcePort), "%s:%d" % (destinationAddress, destinationPort))
            attackEvent.fields["protocol"] = protocol
            attackEvent.fields["inputPackets"] = inputPackets
            attackEvent.fields["inputBytes"] = inputBytes
            attackEvent.fields["outputPackets"] = outputPackets
            attackEvent.fields["outputBytes"] = outputBytes

            return attackEvent
        except:
            if count == 1:
                return None
            elif fileName is None:
                LOG.critical("The line %d has an invalid format.", count)
                raise IOError("The line %d has an invalid format." % count)
            else:
                LOG.critical("The line %d in the file '%s' has an invalid format.", count, fileName)
                raise IOError("The line %d in the file '%s' has an invalid format." % (count, fileName))
