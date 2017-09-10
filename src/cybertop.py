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
The CyberSecurity Topologies related stuff.

@author: Daniele Canavese
"""

import logging
import os
from configparser import SafeConfigParser
from yapsy.PluginManager import PluginManager
from plugins import ActionPlugin
from parsing import Parser
from recipes import RecipesReasoner
from hspl import HSPLReasoner
from mspl import MSPLReasoner

class CyberTop(object):
    """
    The CyberSecurity Topologies main class.
    """
    
    # The configuration file.
    CONFIGURATION_FILES = ["cybertop.cfg", "/etc/cybertop.cfg", os.path.expanduser('~/.cybertop.cfg')]

    def __init__(self):
        """
        Constructor.
        """
        # Configures the logging.
        logging.basicConfig(filename  = "cybertop.log", level = logging.DEBUG, format = "%(asctime)-25s %(levelname)-8s %(message)s")
        logging.getLogger("yapsy").setLevel(logging.WARNING)
        self.logger = logging.getLogger("cybertop")
        defaults = {}
        defaults["recipeDirectory"] = "recipes"
        defaults["pluginsDirectory"] = "plugins"
        defaults["landscapeSchema"] = "xsd/landscape.xsd"
        defaults["recipeSchema"] = "xsd/recipe.xsd"
        defaults["hsplSchema"] = "xsd/hspl.xsd"
        defaults["msplSchema"] = "xsd/mspl.xsd"
        self.configParser = SafeConfigParser(defaults)
        if len(self.configParser.read(self.CONFIGURATION_FILES)) > 0:
            self.logger.debug("Configuration file read.")
        else:
            self.logger.warning("Configuration file not read.")
        self.pluginManager = PluginManager()
        self.pluginManager.setPluginPlaces([self.configParser.get("global", "pluginsDirectory")])
        self.pluginManager.setCategoriesFilter({"Action" : ActionPlugin});
        self.pluginManager.collectPlugins()
        pluginsCount = len(self.pluginManager.getPluginsOfCategory("Action"))
        if pluginsCount > 1:
            self.logger.debug("Found %d plug-ins.", pluginsCount)
        else:
            self.logger.debug("Found %d plug-in.", pluginsCount)
        self.parser = Parser(self.configParser)
        self.recipesReasoner = RecipesReasoner(self.configParser, self.pluginManager)
        self.hsplReasoner = HSPLReasoner(self.configParser, self.pluginManager)
        self.msplReasoner = MSPLReasoner(self.configParser, self.pluginManager)
        self.logger.info("CyberSecurity Topologies initialized.")
    
    def getMSPLs(self, attackFileName, landscapeFileName):
        """
        Retrieve the HSPLs that can be used to mitigate an attack.
        @param attackFileName: the name of the attack file to parse.
        @param landscapeFileName: the name of the landscape file to parse.
        @return: The HSPL set and MSPL set that can mitigate the attack. It is None if the attack is not manageable.
        @raise SyntaxError: When the generated XML is not valid.
        """
        attack = self.parser.getAttack(attackFileName)
        landscape = self.parser.getLandscape(landscapeFileName)
        recipe = self.recipesReasoner.getRecipe(attack, landscape)
        hsplSet = self.hsplReasoner.getHSPLs(attack, recipe, landscape)
        msplSet = self.msplReasoner.getMSPLs(hsplSet, landscape)
        
        if hsplSet is None or msplSet is None:
            return None
        else:
            return [hsplSet, msplSet]
