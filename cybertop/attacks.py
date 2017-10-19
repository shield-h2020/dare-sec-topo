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
Attacks and related events.

@author: Daniele Canavese
"""

class Attack(object):
    """
    An attack.
    """
    
    def __init__(self, severity, attackType, identifier):
        """
        Constructor. It creates an attack without events.
        @param severity: The attack severity. An integer between 1 and 4.
        @param attackType: The attack type.
        @param identifier: The integer identifier of the attack.
        """
        self.severity = severity
        self.type = attackType
        self.identifier = identifier
        self.events = []
    
    def getTimestamp(self):
        """
        Retrieves the attack timestamp.
        @return: The attack timestamp or None if no timestamp is available.
        """
        timestamp = None
        
        for i in self.events:
            if timestamp is None:
                timestamp = i.timestamp
            else:
                timestamp = min(timestamp, i.timestamp)
        
        return timestamp

class AttackEvent(object):
    """
    An attack event.
    """
    
    def __init__(self, timestamp, attacker, target):
        """
        Constructor.
        @param timestamp: The attack timestamp.
        @param attacker: The attacker. It can be an IP, a URL, ...
        @param target: The attack target. It can be an IP, a URL, ...
        """
        self.timestamp = timestamp
        self.attacker = attacker
        self.target = target
        self.fields = {}
