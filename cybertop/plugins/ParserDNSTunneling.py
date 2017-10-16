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
DoS attack events parser plug-in.

@author: Daniele Canavese
"""

from cybertop.plugins import ParserPlugin
from cybertop.attacks import AttackEvent
import re
from cybertop.log import LOG
from dateutil import parser
import ipaddress

class ParserDoS(ParserPlugin):
    """
    Parses a DoS attack event.
    """
    
    def parse(self, fileName, count, line):
        """
        Parses an event line.
        @param fileName: The current file name.
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
            timestamp = parser.parse("%s %s %s %s %s" % (parts[0], parts[1], parts[2], parts[3], parts[4]))
            frameLength = int(parts[6])
            destinationAddress = ipaddress.ip_address(parts[7])
            query = parts[8]
            queryClass = int(parts[9], 16)
            queryType = int(parts[10])
            queryResponseCode = int(parts[11])

            attackEvent = AttackEvent(timestamp, "0.0.0.0/0:53", "%s:*" % destinationAddress)
            attackEvent.fields["frameLength"] = frameLength
            attackEvent.fields["query"] = query
            attackEvent.fields["queryClass"] = queryClass
            attackEvent.fields["queryType"] = queryType
            attackEvent.fields["queryResponseCode"] = queryResponseCode

            return attackEvent
        except:
            if count == 1:
                return None
            else:
                LOG.critical("The line %d in the file '%s' has an invalid format.", count, fileName)
                raise IOError("The line %d in the file '%s' has an invalid format." % (count, fileName))
