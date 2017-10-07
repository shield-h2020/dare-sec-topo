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

import ntpath
import re
from dateutil import parser
import ipaddress
from lxml import etree
from cybertop.attacks import Attack, AttackEvent
from cybertop.util import getLandscapeXSDFile
from cybertop.util import getLandscapeNamespace
from cybertop.log import LOG
import os.path

class Parser(object):
    """
    The file parser.
    """

    def __init__(self, configParser, pluginManager):
        """
        Constructor.
        @param configParser: The configuration parser.
        @param pluginManager: The plug-in manager.
        """
        self.configParser = configParser
        self.pluginManager = pluginManager

    def getAttack(self, fileName):
        """
        Creates an attack object by parsing a CSV file.
        @param fileName: the file name of the CSV file to parse.
        @return: the attack object.
        @raise IOError: if the file has an invalid format or if no suitable parser plug-in is available.
        """
        # First: checks if the file is a regular file.
        if not ntpath.isfile(fileName):
            LOG.critical("The file '%s' is not a regular file.", fileName)
            raise IOError("The file '%s' is not a regular file." % fileName)
        
        # Second: checks the file name format.
        match = re.match("^(Very Low|Very low|very low|Low|low|High|high|Very High|Very high|high)-(.+)?-(\d+)\.csv$", os.path.basename(fileName))
        if not match:
            LOG.critical("The file '%s' has an invalid name.", fileName)
            raise IOError("The file '%s' has an invalid name." % fileName)
        
        # Retrieves the severity, the attack type and the identifier.
        severity = match.group(1).lower()
        if severity == "very low":
            severity = 1
        elif severity == "low":
            severity = 2
        elif severity == "high":
            severity = 3
        else:
            severity = 4
        attackType = match.group(2)
        identifier = int(match.group(3))

        # Finds a suitable parser.
        plugin = None
        for i in self.pluginManager.getPluginsOfCategory("AttackEventParser"):
            pluginAttack = i.details.get("Core", "Attack")
            if pluginAttack == attackType:
                plugin = i
                break
        if plugin is None:
            LOG.critical("No suitable attack event parser found.")
            raise IOError("No suitable attack event parser found")

        # Creates an attack object.
        attack = Attack(severity, attackType, identifier)
                
        # Opens the file and read the events.
        count = 0
        with open(fileName, "rt") as csv:
            for line in csv:
                count += 1
                event = plugin.plugin_object.parse(fileName, count, line)
                if event is not None:
                    attack.events.append(event)
        
        # Third: checks if there are some events.
        if count <= 1:
            LOG.critical("The file '%s' is empty.", fileName)
            raise IOError("The file '%s' is empty." % fileName)
                    
        LOG.info("Parsed an attack of type '%s' with severity %d and containing %d events.", attack.type, attack.severity, len(attack.events))
        return attack
    
    def getLandscape(self, fileName):
        """
        Creates a landscape map by parsing an XML file.
        @param fileName: the file name of the XML file to parse.
        @return: the landscape map.
        @raise IOError: if the file has an invalid format.
        """
        schema = etree.XMLSchema(etree.parse(getLandscapeXSDFile()))
        parser = etree.XMLParser(schema = schema)
        
        if not os.path.exists(fileName):
            LOG.critical("The file '%s' does not exist", fileName)
            raise IOError("The file '%s' does not exist", fileName)
            
        root = etree.parse(fileName, parser).getroot()
        landscape = {}
        for i in root:
            identifier = i.attrib["id"]
            capabilities = set()
            for j in i.findall("{%s}capability" % getLandscapeNamespace()):
                capabilities.add(j.text)
            landscape[identifier] = capabilities
        
        LOG.info("Landscape with %d IT resources read.", len(landscape))
        return landscape
