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
from cybertop.util import getRecipeDirectory
from cybertop.util import getRecipeXSDFile
from cybertop.util import getRecipeNamespace
from cybertop.log import LOG

class RecipesReasoner(object):
    """
    Finds the recipes that can be used to mitigate an attack.
    """
    
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
            schema = etree.XMLSchema(etree.parse(getRecipeXSDFile()))
            parser = etree.XMLParser(schema = schema)
        
            recipes = set()
            recipesDirectory = getRecipeDirectory()
            # We find all the valid recipes.
            for file in os.listdir(recipesDirectory):
                if file.endswith(".xml"):
                    path = os.path.join(recipesDirectory, file)
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
            raise IOError("Unable to read the recipe directory '%s'" % recipesDirectory)
        
    def __filterNonEnforceableRecipes(self, recipes, landscape):
        """
        Filters the recipes that cannot be enforced.
        @param recipes: The recipes to filter.
        @param landscape: The landscape.
        @return: The recipes that can be enforced. It can be an empty list.
        """
        validRecipes = set()
        for i in recipes:
            recipeAction = i.findtext("{%s}action" % getRecipeNamespace())
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
            LOG.debug("Removed %d non-enforceable recipe, %d remaining.", notEnforceable, len(validRecipes))
        elif notEnforceable > 1:
            LOG.debug("Removed %d non-enforceable recipes, %d remaining.", notEnforceable, len(validRecipes))
        return validRecipes

    def __filterTooStrictRecipes(self, recipes, attack):
        """
        Filters the recipes that are too strict and do not match any attack event.
        @param recipes: The recipes to filter.
        @param attack: The attack to mitigate.
        @return: The recipes that can be enforced. It can be an empty list.
        """
        validRecipes = set()

        for i in recipes:
            recipeFilters = i.find("{%s}filters" % getRecipeNamespace())
            evaluation = "or"
            if recipeFilters is None:
                validRecipes.add(i)
            else:
                if "evaluation" in recipeFilters.attrib.keys():
                    evaluation = recipeFilters.attrib["evaluation"]
                for j in attack.events:
                    if evaluation == "or":
                        test = False
                    else:
                        test = True
                    for k in self.pluginManager.getPluginsOfCategory("Filter"):
                        pluginTag = k.details.get("Core", "Tag")
                        filterValues = recipeFilters.findall("{%s}%s" % (getRecipeNamespace(), pluginTag))
                        for l in filterValues:
                            t = k.plugin_object.filter(l.text, j)
                            if evaluation == "or":
                                test = test or t
                            else:
                                test = test and t
                    if not test:
                        validRecipes.add(i)
                        break

        tooStrict = len(recipes) - len(validRecipes)
        if tooStrict == 1:
            LOG.debug("Removed %d too strict recipe, %d remaining.", tooStrict, len(validRecipes))
        elif tooStrict > 1:
            LOG.debug("Removed %d too strict recipes, %d remaining.", tooStrict, len(validRecipes))
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
            recipeAction = i.findtext("{%s}action" % getRecipeNamespace())
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
        recipes = self.__filterTooStrictRecipes(recipes, attack)
        recipe = self.__getBestRecipe(recipes, landscape)
        if recipe is None:
            return None
        else:
            recipeName = recipe.findtext("{%s}name" % getRecipeNamespace())
            LOG.info("Recipe '%s' chosen.", recipeName)
            return recipe
