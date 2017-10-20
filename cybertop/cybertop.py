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
from configparser import ConfigParser
from yapsy.PluginManager import PluginManager
from cybertop.plugins import ActionPlugin
from cybertop.plugins import ParserPlugin
from cybertop.plugins import FilterPlugin
from cybertop.parsing import Parser
from cybertop.recipes import RecipesReasoner
from cybertop.hspl import HSPLReasoner
from cybertop.mspl import MSPLReasoner
import pika
from lxml import etree
from cybertop.util import getPluginDirectory
from cybertop import log
from cybertop.log import LOG
from cybertop.util import getPIDFile
from cybertop.util import getConfigurationFile


class CyberTop(pyinotify.ProcessEvent):
    """
    The CyberSecurity Topologies main class.
    """

    def __init__(self, configurationFileName=None,
                 logConfigurationFileName=None):
        """
        Constructor.
        @param configurationFileName: the name of the configuration file to
                                      parse.
        @param logConfigurationFileName: the name of the log configuration file
                                         to use.
        """
        # Configures the logging.
        log.load_settings(logConfigurationFileName)

        # Configures the configuration file parser.
        self.configParser = ConfigParser()
        if configurationFileName is None:
            c = self.configParser.read(getConfigurationFile())
        else:
            c = self.configParser.read(configurationFileName)
        if len(c) > 0:
            LOG.debug("Configuration file '%s' read." % c[0])
        else:
            LOG.critical("Cannot read the configuration file from '%s'." %
                         configurationFileName)
            raise IOError("Cannot read the configuration file from '%s'" %
                          configurationFileName)

        # Configures the plug-ins.
        self.pluginManager = PluginManager()
        self.pluginManager.setPluginPlaces([getPluginDirectory()])
        self.pluginManager.setCategoriesFilter({"Action": ActionPlugin,
                                                "Parser": ParserPlugin,
                                                "Filter": FilterPlugin})
        self.pluginManager.collectPlugins()
        pluginsCount = len(self.pluginManager.getPluginsOfCategory("Parser"))
        if pluginsCount > 1:
            LOG.info("Found %d attack event parser plug-ins.", pluginsCount)
        else:
            LOG.info("Found %d attack event parser plug-in.", pluginsCount)
        pluginsCount = len(self.pluginManager.getPluginsOfCategory("Filter"))
        if pluginsCount > 1:
            LOG.info("Found %d attack event filter plug-ins.", pluginsCount)
        else:
            LOG.info("Found %d attack event filter plug-in.", pluginsCount)
        pluginsCount = len(self.pluginManager.getPluginsOfCategory("Action"))
        if pluginsCount > 1:
            LOG.info("Found %d action plug-ins.", pluginsCount)
        else:
            LOG.info("Found %d action plug-in.", pluginsCount)

        # Loads all the sub-modules.
        self.parser = Parser(self.configParser, self.pluginManager)
        self.recipesReasoner = RecipesReasoner(self.configParser,
                                               self.pluginManager)
        self.hsplReasoner = HSPLReasoner(self.configParser, self.pluginManager)
        self.msplReasoner = MSPLReasoner(self.configParser, self.pluginManager)
        LOG.info("CyberSecurity Topologies initialized.")

    def getMSPLs(self, attackFileName, landscapeFileName):
        """
        Retrieve the HSPLs that can be used to mitigate an attack.
        @param attackFileName: the name of the attack file to parse.
        @param landscapeFileName: the name of the landscape file to parse.
        @return: The HSPL set and MSPL set that can mitigate the attack. It is
                 None if the attack is not manageable.
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

    def start(self, foreground=False):
        """
        Starts the CyberTop policy engine
        @param foreground: A value stating if the daemon must be launched in foreground or background mode.
        """

        wm = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(wm, self)
        wm.add_watch(self.configParser.get("global", "watchedDirectory"),
                     pyinotify.IN_CLOSE_WRITE, rec=True, auto_add=True)
        if(not foreground):
            notifier.loop(daemonize=True, pid_file=getPIDFile())
        else:
            notifier.loop(daemonize=False)

    def process_IN_CLOSE_WRITE(self, event):
        """
        Handles a file creation.
        @param event: The file event.
        """
        try:
            # First, translate the CSV in HSPL, MSPL sets
            [hsplSet, msplSet] = self.getMSPLs(event.pathname,
                                               self.configParser.
                                               get("global",
                                                   "landscapeFile"))

            # Then, if extra logging is activated, print HSPL (and/or MSPL)
            # to an external file
            if self.configParser.has_option("global", "hsplsFile"):
                with open(self.configParser.get("global", "hsplsFile"), "w") as f:
                    f.write(etree.tostring(hsplSet, pretty_print=True).
                            decode())
            if self.configParser.has_option("global", "msplsFile"):
                with open(self.configParser.get("global", "msplsFile"), "w") as f:
                    f.write(etree.tostring(msplSet, pretty_print=True).
                            decode())

            # Finally, sends everything to RabbitMQ.

            if (self.configParser.has_option("global", "dashboardHost") and
                self.configParser.has_option("global", "dashboardPort") and
                self.configParser.has_option("global", "dashboardExchange") and
                self.configParser.has_option("global", "dashboardTopic") and
                self.configParser.has_option("global", "dashboardAttempts") and
                    self.configParser.has_option("global", "dashboardRetryDelay")):

                host = self.configParser.get("global", "dashboardHost")
                port = self.configParser.getint("global", "dashboardPort")
                connectionAttempts = self.configParser.getint("global",
                                                              "dashboardAttempts")
                retryDelay = self.configParser.getint("global",
                                                      "dashboardRetryDelay")
                connection = pika.BlockingConnection(pika.ConnectionParameters(
                    host=host,
                    port=port,
                    connection_attempts=connectionAttempts,
                    retry_delay=retryDelay,
                    blocked_connection_timeout=300))
                self.channel = connection.channel()
                self.channel.exchange_declare(exchange=self.configParser.
                                              get("global", "dashboardExchange"),
                                              exchange_type='topic')
                LOG.info("Connected to the dashboard at " + host + ":" + str(port))
                hsplString = etree.tostring(hsplSet).decode()
                msplString = etree.tostring(msplSet).decode()
                content = self.configParser.get("global", "dashboardContent")
                if content == "HSPL":
                    message = hsplString
                elif content == "MSPL":
                    message = msplString
                else:
                    message = hsplString + msplString

                LOG.info("Pushing the remediation to the dashboard")
                exchange = self.configParser.get("global", "dashboardExchange")
                topic = self.configParser.get("global", "dashboardTopic")
                self.channel.basic_publish(exchange=exchange,
                                           routing_key=topic, body=message)
                LOG.debug("RabbitMQ exchange: " + exchange + " topic: " +
                          topic)
                LOG.info("Remediation forwarded to the dashboard")
                self.channel.close()
                LOG.info("Connection with the dashboard closed")
        except BaseException as e:
            LOG.critical(str(e))
            if self.channel is not None:
                if not self.channel.is_closed:
                    self.channel.close()
