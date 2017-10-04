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

import pyinotify
import os
from configparser import ConfigParser
from yapsy.PluginManager import PluginManager
from cybertop.plugins import ActionPlugin
from cybertop.parsing import Parser
from cybertop.recipes import RecipesReasoner
from cybertop.hspl import HSPLReasoner
from cybertop.mspl import MSPLReasoner
import pika
from lxml import etree
import signal
from cybertop.util import get_plugin_impl_path
from cybertop import log
from cybertop.log import LOG

class CyberTop(pyinotify.ProcessEvent):
    """
    The CyberSecurity Topologies main class.
    """
    
    # The configuration file.
    CONFIGURATION_FILES = ["./cybertop.cfg", "/etc/cybertop.cfg", os.path.expanduser('~/.cybertop.cfg')]
    # The pid file.
    PID_FILE = "/tmp/cybertop.pid"
    # The version number.
    VERSION = "0.2"

    def __init__(self, configurationFileName = None, 
        logConfigurationFileName = None):
        """
        Constructor.
        @param configurationFileName: the name of the configuration file to parse.
        """
        # Configures the logging.

        log.load_settings(logConfigurationFileName)
        
        # Configures the configuration file parser.
        self.configParser = ConfigParser()
        if configurationFileName is None:
            c = self.configParser.read(self.CONFIGURATION_FILES)
        else:
            c = self.configParser.read(configurationFileName)
        if len(c) > 0:
            LOG.debug("Configuration file %s read.", c[0])
        else:
            LOG.critical("Configuration file not read.")
            raise IOError("Cannot read configuration file from %s.",
                configurationFileName)

        # Configures the plug-ins.
        self.pluginManager = PluginManager()
        self.pluginManager.setPluginPlaces([get_plugin_impl_path()])
        self.pluginManager.setCategoriesFilter({"Action" : ActionPlugin})
        self.pluginManager.collectPlugins()
        pluginsCount = len(self.pluginManager.getPluginsOfCategory("Action"))
        if pluginsCount > 1:
            LOG.debug("Found %d plug-ins.", pluginsCount)
        else:
            LOG.debug("Found %d plug-in.", pluginsCount)
        # Loads all the sub-modules.
        self.parser = Parser(self.configParser)
        self.recipesReasoner = RecipesReasoner(self.configParser, self.pluginManager)
        self.hsplReasoner = HSPLReasoner(self.configParser, self.pluginManager)
        self.msplReasoner = MSPLReasoner(self.configParser, self.pluginManager)
        LOG.info("CyberSecurity Topologies initialized.")
    
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

    def start(self):
        """
        Starts the CyberTop daemon.
        """        
        if (self.configParser.has_option("global", "dashboardURL") and
            self.configParser.has_option("global", "dashboardQueue") and
            self.configParser.has_option("global", "dashboardAttempts") and
            self.configParser.has_option("global", "dashboardRetryDelay")):
            host = self.configParser.get("global", "dashboardURL")
            connectionAttempts = self.configParser.get("global", "dashboardAttempts")
            retryDelay = self.configParser.get("global", "dashboardRetryDelay")
            connection = pika.BlockingConnection(pika.ConnectionParameters(
                host = host,
                connection_attempts = connectionAttempts,
                retry_delay = retryDelay))
            self.channel = connection.channel()
            self.channel.queue_declare(queue = self.configParser.get("global", "dashboardQueue"))
            LOG.info("Connected to the dashboard.")
        else:
            self.channel = None
        
        wm = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(wm, self)
        wm.add_watch(self.configParser.get("global", "watchedDirectory"), pyinotify.IN_CREATE, rec = True, auto_add = True)
        notifier.loop()#(daemonize = True, pid_file = self.PID_FILE)

    def stop(self):
        """
        Stops the CyberTop daemon.
        """
        if os.path.isfile(self.PID_FILE): 
            with open(self.PID_FILE) as d:
                pid = int(d.read())
                os.kill(pid, signal.SIGTERM)
                os.remove(self.PID_FILE)
        else:
            print("No daemon running.")

    def process_IN_CREATE(self, event):
        try:
            [hsplSet, msplSet] = self.getMSPLs(event.pathname, self.configParser.get("global", "landscapeFile"))
            hsplString = etree.tostring(hsplSet).decode()
            msplString = etree.tostring(msplSet).decode()
            
            message = hsplString + msplString
            
            # Sends everything to RabbitMQ.
            if self.channel is not None:
                queue = self.configParser.get("global", "dashboardQueue")
                self.channel.basic_publish(exchange = "", routing_key = queue, body = message)
            
            # Appends everything to the dashboard dump file.
            if self.configParser.has_option("global", "dashboardFile"):
                with open(self.configParser.get("global", "dashboardFile"), "a") as f:
                    f.write(message)
        except:
            LOG.critical("Error while transferring the HSPL and MSPL to dashboard")
            raise IOError("Cannot transfer HSPL and MSPL to dashboard")


            raise
