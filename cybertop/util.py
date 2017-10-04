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
Utility classes for the whole cybertop package

@author: Marco De Benedictis
"""

import pkg_resources

# Global constants
PLUGIN_IMPL_DIR_NAME = 'plugin_impl'
XSD_DIR_NAME = 'xsd'
RECIPES_DIR_NAME = 'recipes'
LANDSCAPE_XSD_FILE_NAME = 'landscape.xsd'
HSPL_XSD_FILE_NAME = 'hspl.xsd'
MSPL_XSD_FILE_NAME = 'mspl.xsd'
RECIPE_XSD_FILE_NAME = 'recipe.xsd'

def get_plugin_impl_path():
    """
    Retrieve the path of the plugin implementation directory
    @return: The path of the requested directory.
    """
    return pkg_resources.resource_filename(__name__, PLUGIN_IMPL_DIR_NAME)

def get_recipes_path():
    """
    Retrieve the path of the recipes directory
    @return: The path of the requested directory.
    """
    return pkg_resources.resource_filename(__name__, RECIPES_DIR_NAME)

def get_landscape_xsd_path():
    """
    Retrieve the path of the landscape XSD schema
    @return: The path of the requested file.
    """
    return pkg_resources.resource_filename(__name__,
        '/'.join((XSD_DIR_NAME, LANDSCAPE_XSD_FILE_NAME)))

def get_recipe_xsd_path():
    """
    Retrieve the path of the recipe XSD schema
    @return: The path of the requested file.
    """
    return pkg_resources.resource_filename(__name__,
        '/'.join((XSD_DIR_NAME, RECIPE_XSD_FILE_NAME)))

def get_hspl_xsd_path():
    """
    Retrieve the path of the HSPL XSD schema
    @return: The path of the requested file.
    """
    return pkg_resources.resource_filename(__name__,
        '/'.join((XSD_DIR_NAME, HSPL_XSD_FILE_NAME)))

def get_mspl_xsd_path():
    """
    Retrieve the path of the MSPL XSD schema
    @return: The path of the requested file.
    """
    return pkg_resources.resource_filename(__name__,
        '/'.join((XSD_DIR_NAME, MSPL_XSD_FILE_NAME)))


