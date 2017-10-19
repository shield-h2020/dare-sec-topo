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
Logging helper.

@author: Paolo Smiraglia
"""

import logging
import logging.config
import os
import sys


# default logging settings
LOG = logging.getLogger("cybertop")
LOG.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)-25s %(levelname)-8s %(message)s")
ch.setFormatter(formatter)
LOG.addHandler(ch)
logging.getLogger("yapsy").setLevel(logging.WARNING)

def load_settings(cfg_file):
    """Load logging settings from .INI file.

    Args:
        cfg_file (str): Path to logging configuration file.

    """
    global LOG
    if not os.path.exists(cfg_file):
        LOG.warning(("Logging configuration file '%s' not found!" +
                     "Default values will be used...") % cfg_file)
    else:
        LOG.debug("Reading logging configuration from '%s'" % cfg_file)
        logging.config.fileConfig(cfg_file)
        LOG = logging.getLogger("cybertop")
