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
import re

"""
Input bytes filter plug-in.

@author: Daniele Canavese
"""

from cybertop.plugins import FilterPlugin

class FilterInputBytes(FilterPlugin):
    """
    Parses a DoS attack event.
    """
    
    def filter(self, value, attackEvent):
        """
        Filters an attack event.
        @param value: The optional value for the filter.
        @param attackEvent: The attack event to analyze.
        @return: True if the event must be accepted, False if the event must be discarded.
        """
        inputBytes = attackEvent.fields["inputBytes"]
        groups = re.findall("(==|!=|<|<=|>|>=)(\d+)", value)
        relationship = groups[0][0]
        number = int(groups[0][1])
        
        if relationship == "==" and inputBytes == number:
            return True
        elif relationship == "!=" and inputBytes != number:
            return True
        elif relationship == "<" and inputBytes < number:
            return True
        elif relationship == "<=" and inputBytes <= number:
            return True
        elif relationship == ">" and inputBytes > number:
            return True
        elif relationship == ">=" and inputBytes >= number:
            return True
        else:
            return False
