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
CSV parsing & co.

@author: Daniele Canavese
"""

import logging
import ntpath
import re
from dateutil import parser
import ipaddress
from lxml import etree
from attacks import Attack, AttackEvent

class Parser(object):
    """
    The file parser.
    """

    # The lanscape namespace.
    NAMESPACE_LANDSCAPE = "http://security.polito.it/shield/landscape"

    def __init__(self, configParser):
        """
        Constructor.
        @param configParser: The configuration parser.
        """
        self.logger = logging.getLogger("parser")
        self.configParser = configParser
        self.logger.debug("Parser initialized.")

    def getAttack(self, fileName):
        """
        Creates an attack object by parsing a CSV file.
        @param fileName: the file name of the CSV file to parse.
        @return: the attack object.
        @raise IOError: if the file has an invalid format.
        """
        # First: checks if the file is a regular file.
        if not ntpath.isfile(fileName):
            self.logger.critical("The file '%s' is not a regular file.", fileName)
            raise IOError("The file '%s' is not a regular file." % fileName)
        
        # Second: checks the file name format.
        match = re.match("^([1234])-(.+)?-(\d+)\.csv$", fileName)
        if not match:
            self.logger.critical("The file '%s' has an invalid name.", fileName)
            raise IOError("The file '%s' has an invalid name." % fileName)
        
        # Retrieves the severity, the attack type and the identifier.
        severity = int(match.group(1))
        attackType = match.group(2)
        identifier = int(match.group(3))

        # Creates an attack object.
        attack = Attack(severity, attackType, identifier)
        
        # Opens the file and read the events.
        count = 0
        with open(fileName, "rt") as csv:
            for line in csv:
                count += 1
                if count > 1:
                    parts = re.split("\s", line.rstrip())
                    # Columns check.
                    if len(parts) != 19:
                        self.logger.critical("The file '%s' has an invalid format.", fileName)
                        raise IOError("The file '%s' has an invalid format." % fileName)
                    # Various format checks.
                    if not (re.match("\d+-\d+-\d+", parts[0]) and re.match("\d+:\d+:\d+", parts[1]) and re.match("\d+\.\d+\.\d+\.\d+", parts[9]) and
                        re.match("\d+\.\d+\.\d+\.\d+", parts[10]) and re.match("\d+", parts[11]) and re.match("\d+", parts[12]) and
                        re.match("TCP|UDP", parts[13])):
                        self.logger.critical("The file '%s' has an invalid format.", fileName)
                        raise IOError("The file '%s' has an invalid format." % fileName)
                    timestamp = parser.parse("%s %s" % (parts[0], parts[1]))
                    sourceAddress = ipaddress.ip_address(parts[9])
                    destinationAddress = ipaddress.ip_address(parts[10])
                    sourcePort = int(parts[11])
                    destinationPort = int(parts[12])
                    protocol = parts[13]
                    attack.events.append(AttackEvent(timestamp, sourceAddress, sourcePort, destinationAddress, destinationPort, protocol))
        
        # Third: checks if there are some events.
        if count <= 1:
            self.logger.critical("The file '%s' is empty.", fileName)
            raise IOError("The file '%s' is empty." % fileName)
                    
        self.logger.info("Parsed an attack of type '%s' with severity %d and containing %d events.", attack.type, attack.severity, len(attack.events))
        return attack
    
    def getLandscape(self, fileName):
        """
        Creates a landscape map by parsing an XML file.
        @param fileName: the file name of the XML file to parse.
        @return: the landscape map.
        @raise IOError: if the file has an invalid format.
        """
        landscapeSchema = self.configParser.get("global", "landscapeSchema")
        schema = etree.XMLSchema(etree.parse(landscapeSchema))
        parser = etree.XMLParser(schema = schema)

        root = etree.parse(fileName, parser).getroot()
        landscape = {}
        for i in root:
            identifier = i.attrib["id"]
            capabilities = set()
            for j in i.findall("{%s}capability" % self.NAMESPACE_LANDSCAPE):
                capabilities.add(j.text)
            landscape[identifier] = capabilities
        
        self.logger.info("Landscape with %d IT resources read.", len(landscape))
        return landscape
