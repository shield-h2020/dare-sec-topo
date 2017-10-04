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
Recipes and attack mitigation.

@author: Daniele Canavese
"""

import re
from dateutil import parser
import os
from lxml import etree
from cybertop.util import get_recipes_path, get_recipe_xsd_path
from cybertop.log import LOG

class RecipesReasoner(object):
    """
    Finds the recipes that can be used to mitigate an attack.
    """

    # The recipe namespace.
    NAMESPACE_RECIPE = "http://security.polito.it/shield/recipe"
    
    def __init__(self, configParser, pluginManager):
        """
        Constructor.
        @param configParser: The configuration parser.
        @param pluginManager: The plug-in manager.
        """
        self.configParser = configParser
        self.pluginManager = pluginManager
    
    def __getRecipes(self, attack):
        """
        Retrieves all the recipes that can be used to mitigate an attack.
        @param attack: The attack to mitigate.
        @return: The set of recipes that can mitigate the attack. It is an empty list if no recipe is available.
        @raise IOError: if a file or directory cannot be read.
        """
        
        try:
            # Parses the XML schema.
            schema = etree.XMLSchema(etree.parse(get_recipe_xsd_path()))
            parser = etree.XMLParser(schema = schema)
        
            recipes = set()
            recipes_path = get_recipes_path()
            # We find all the valid recipes.
            for file in os.listdir(recipes_path):
                if file.endswith(".xml"):
                    path = os.path.join(recipes_path, file)
                    try:
                        recipeSet = etree.parse(path, parser).getroot()
                        minSeverity = int(recipeSet.attrib["minSeverity"])
                        maxSeverity = int(recipeSet.attrib["maxSeverity"])
                        attackType = recipeSet.attrib["type"]
                        if attack.type == attackType and attack.severity >= minSeverity and attack.severity <= maxSeverity:
                            recipes.update(recipeSet.getchildren())
                    except etree.XMLSyntaxError:
                        LOG.warning("The file '%s' is an invalid recipe.", path)
                        
            LOG.debug("Found %s suitable recipes.", len(recipes))
            return recipes
        except FileNotFoundError:
            raise IOError("Unable to read the recipe directory '%s'" % recipes_path)
        
    def __filterNonEnforceableRecipes(self, recipes, landscape):
        """
        Filters the recipes that cannot be enforced.
        @param recipes: The recipes to filter.
        @param landscape: The landscape.
        @return: The recipes that can be enforced. It can be an empty list.
        """
        validRecipes = set()
        for i in recipes:
            recipeAction = i.findtext("{%s}action" % self.NAMESPACE_RECIPE)
            for j in self.pluginManager.getPluginsOfCategory("Action"):
                pluginAction = j.details.get("Core", "Action")
                pluginCapabilities = set(re.split("\s*,\s*", j.details.get("Core", "Capabilities")))
                if recipeAction == pluginAction:
                    for capabilities in landscape.values():
                        if pluginCapabilities.issubset(capabilities):
                            validRecipes.add(i)
                            break
        
        notEnforceable = len(recipes) - len(validRecipes)
        if notEnforceable == 1:
            LOG.debug("Removed %s non-enforceable recipe, %d remaining.", notEnforceable, len(validRecipes))
        elif notEnforceable > 1:
            LOG.debug("Removed %s non-enforceable recipes, %d remaining.", notEnforceable, len(validRecipes))
        return validRecipes

    def __getBestRecipe(self, recipes, landscape):
        """
        Gets the best recipe.
        @param recipes: The recipes to search for.
        @param landscape: The landscape.
        @return: The best recipe. It is None if the recipes list is empty.
        """
        recipe = None
        score = None
        # Picks the recipe with the highest score.
        for i in recipes:
            recipeAction = i.findtext("{%s}action" % self.NAMESPACE_RECIPE)
            for j in self.pluginManager.getPluginsOfCategory("Action"):
                pluginAction = j.details.get("Core", "Action")
                pluginScore = j.details.get("Core", "Score")
                pluginCapabilities = set(re.split("\s*,\s*", j.details.get("Core", "Capabilities")))
                if recipeAction == pluginAction:
                    for capabilities in landscape.values():
                        if pluginCapabilities.issubset(capabilities):
                            if score is None or pluginScore > score:
                                score = pluginScore
                                recipe = i
            
        return recipe

    def getRecipe(self, attack, landscape):
        """
        Retrieve the best recipe that can be used to mitigate an attack.
        @param attack: The attack to mitigate.
        @param landscape: The landscape.
        @return: The recipes that can mitigate the attack. It is None if no recipe is available.
        @raise IOError: if a file or directory cannot be read.
        """
        recipes = self.__getRecipes(attack)
        recipes = self.__filterNonEnforceableRecipes(recipes, landscape)
        recipe = self.__getBestRecipe(recipes, landscape)

        recipeName = recipe.findtext("{%s}name" % self.NAMESPACE_RECIPE)
        LOG.info("Recipe '%s' chosen.", recipeName)
        return recipe
