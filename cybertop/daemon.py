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

from cybertop.cybertop import CyberTop
from sys import stderr
import argparse

"""
The CyberSecurity Topologies daemon.

@author: Daniele Canavese
"""

parser = argparse.ArgumentParser(description = "Manages the CyberSecurity Topologies daemon.")
parser.add_argument("--version", action = "version", version = "CyberSecurity Topologies v%s" % CyberTop.VERSION)
parser.add_argument("--configuration", type = argparse.FileType("r"), help = "specifies the configuration file")
parser.add_argument("--start", action = "store_true", help = "starts the daemon")
parser.add_argument("--stop", action = "store_true", help = "stops the daemon")

args = parser.parse_args()

if args.configuration is None:
    configuration = None
else:
    configuration = args.configuration.name

if args.start:
        cybertop = CyberTop(configuration)
        cybertop.start()
elif args.stop:
        cybertop = CyberTop(configuration)
        cybertop.stop()
else:
    print("No action specified", file = stderr)
