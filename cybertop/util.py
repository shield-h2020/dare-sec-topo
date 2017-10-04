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

def get_plugin_impl_path():
    """
    Retrieve the path of the plugin implementation directory
    @return: The path of the requested directory.
    """
    return pkg_resources.resource_filename(__name__, PLUGIN_IMPL_DIR_NAME)

def get_plugina_impl_path():
    """
    Retrieve the path of the plugin implementation directory
    @return: The path of the requested directory.
    """
    return pkg_resources.resource_filename(__name__, PLUGIN_IMPL_DIR_NAME)

