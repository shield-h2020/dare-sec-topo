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

from cybertop import CyberTop

"""
The CyberSecurity Topologies daemon.

@author: Daniele Canavese
"""

from sys import argv
from sys import stderr
from sys import stdout

if len(argv) == 1:
    print >> stderr, "No arguments. Type", argv[0], "--help for help."
elif len(argv) == 2:
    if argv[1] == "--help":
        print >> stdout, "Syntax:", argv[0], "<command>"
        print >> stdout, "Available commands:"
        print >> stdout, "  --help               displays this help screen"
        print >> stdout, "  --start <landscape>  starts the daemon using the specified landscape file"
        print >> stdout, "  --stop               stops the daemon"
    else:
        print >> stderr, "The command", argv[1], "is unknown."
elif len(argv) == 3:
    if argv[1] == "--start":
        cybertop = CyberTop()
        cybertop.start(argv[2])
else:
    print >> stderr, "Too many arguments."
