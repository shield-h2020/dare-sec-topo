#!/bin/bash
#
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

# The Python interpreter must be the one with the cybertop module installed

PYTHON_SHEBANG="#!/usr/bin/env python"

# Check if user is root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root"
    exit 1
fi

# Create an executable in /usr/local/bin with proper Python interpreter

echo "Creating executable script in /usr/local/bin"

echo $PYTHON_SHEBANG | cat - daemon.py > \
    /usr/local/bin/cybertop-daemon

chmod a+x /usr/local/bin/cybertop-daemon

# Copy systemd configuration file in /etc/default

echo "Copying cybertop configuration file to /etc/default dir"

cp systemd/cybertop /etc/default/cybertop

# Copy systemd init file in /etc/systemd/system

echo "Copying cybertop systemd init file to /etc/systemd/system dir"

cp systemd/cybertop.service /etc/systemd/system/cybertop.service

# Enable cybertop systemd

systemctl enable cybertop.service
