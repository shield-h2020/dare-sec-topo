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
Utility stuff for the whole CyberTop tool.

@author: Marco De Benedictis, Daniele Canavese
"""

from pkg_resources import resource_filename

# The plug-in directory.
PLUGIN_DIRECTORY = "plugins"
# The landscape XSD file.
LANDSCAPE_XSD_FILE = "xsd/landscape.xsd"
# The lanscape namespace.
LANDSCAPE_NAMESPACE = "http://security.polito.it/shield/landscape"
# The recipes directory.
RECIPE_DIRECTORY = "recipes"
# The recipe XSD file.
RECIPE_XSD_FILE = "xsd/recipe.xsd"
# The recipes namespace.
RECIPE_NAMESPACE = "http://security.polito.it/shield/recipe"
# The HSPLs XSD file.
HSPL_XSD_FILE = "xsd/hspl.xsd"
# The HSPLs namespace.
HSPL_NAMESPACE = "http://security.polito.it/shield/hspl"
# The MSPLs XSD file.
MSPL_XSD_FILE = "xsd/mspl.xsd"
# The MSPLs namespace.
MSPL_NAMESPACE = "http://security.polito.it/shield/mspl"
# The XSI namespace.
XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
# The PID file.
PID_FILE = "/tmp/cybertop.pid"
# The configuration file.
CONFIGURATION_FILE="/etc/cybertop.cfg"
# The version.
VERSION="0.5"

def getPluginDirectory():
    """
    Retrieve the path of the plug-ins directory.
    @return: The path of the requested directory.
    """
    return resource_filename(__name__, PLUGIN_DIRECTORY)

def getRecipeDirectory():
    """
    Retrieve the path of the recipes directory.
    @return: The path of the requested directory.
    """
    return resource_filename(__name__, RECIPE_DIRECTORY)

def getRecipeNamespace():
    """
    Retrieve the namespace of the recipes XML.
    @return: The namespace of the recipe XML.
    """
    return RECIPE_NAMESPACE

def getRecipeXSDFile():
    """
    Retrieve the path of the recipe XSD file.
    @return: The path of the requested file.
    """
    return resource_filename(__name__, RECIPE_XSD_FILE)

def getLandscapeXSDFile():
    """
    Retrieve the path of the landscape XSD file.
    @return: The path of the requested file.
    """
    return resource_filename(__name__, LANDSCAPE_XSD_FILE)

def getLandscapeNamespace():
    """
    Retrieve the namespace of the landscape XML.
    @return: The namespace of the landscape XML.
    """
    return LANDSCAPE_NAMESPACE

def getHSPLXSDFile():
    """
    Retrieve the path of the HSPL XSD file.
    @return: The path of the requested file.
    """
    return resource_filename(__name__, HSPL_XSD_FILE)

def getHSPLNamespace():
    """
    Retrieve the namespace of the HSPL XML.
    @return: The namespace of the HSPL XML.
    """
    return HSPL_NAMESPACE

def getMSPLXSDFile():
    """
    Retrieve the path of the MSPL XSD file.
    @return: The path of the requested file.
    """
    return resource_filename(__name__, MSPL_XSD_FILE)

def getMSPLNamespace():
    """
    Retrieve the namespace of the MSPL XML.
    @return: The namespace of the MSPL XML.
    """
    return MSPL_NAMESPACE

def getXSINamespace():
    """
    Retrieve the namespace of the XSI XML.
    @return: The namespace of the XSI XML.
    """
    return XSI_NAMESPACE

def getPIDFile():
    """
    Retrieve the path of the PID file.
    @return: The path of the requested file.
    """
    return PID_FILE

def getConfigurationFile():
    """
    Retrieve the path of the configuration file.
    @return: The path of the requested file.
    """
    return CONFIGURATION_FILE

def getVersion():
    """
    Retrieve the version number.
    @return: The version number.
    """
    return VERSION
