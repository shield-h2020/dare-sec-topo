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

import threading
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
from csv import reader
from csv import Sniffer
from re import match
from re import IGNORECASE


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
        # Starts with no attack info.
        self.attacks = {}
        # Connection to the DARE rabbitMQ queue
        self.r_connection = None
        self.r_channel = None
        self.r_closingConnection = False
        LOG.info("CyberSecurity Topologies initialized.")

    def start(self):
        input = self.configParser.get("global", "inputMethod")
        LOG.info("Input method: " + input)
        if input == "queue":
            self.listenRabbitMQ()
        elif input == "csv":
            self.listenFolder()
        elif input == "all":
            self.spawnThreads()
        else:
            LOG.error("Unknown input method chosen (queue, csv allowed)")
            return
        LOG.info("Cybertop started")

    def spawnThreads(self):
        t_rabbit = threading.Thread(target=self.listenRabbitMQ)
        t_csv = threading.Thread(target=self.listenFolder)
        t_rabbit.start()
        t_csv.start()

        t_rabbit.join()
        t_csv.join()

    def getMSPLsFromFile(self, attackFileName, landscapeFileName):
        """
        Retrieve the HSPLs that can be used to mitigate an attack.
        @param attackFileName: the name of the attack file to parse.
        @param landscapeFileName: the name of the landscape file to parse.
        @return: The HSPL set and MSPL set that can mitigate the attack. It is
                 None if the attack is not manageable.
        @raise SyntaxError: When the generated XML is not valid.
        """
        attack = self.parser.getAttackFromFile(attackFileName)
        landscape = self.parser.getLandscape(landscapeFileName)
        recipe = self.recipesReasoner.getRecipe(attack, landscape)
        hsplSet = self.hsplReasoner.getHSPLs(attack, recipe, landscape)
        msplSet = self.msplReasoner.getMSPLs(hsplSet, landscape)

        if hsplSet is None or msplSet is None:
            return None
        else:
            return [hsplSet, msplSet]

    def getMSPLsFromList(self, identifier, severity, attackType, attackList,
                         landscapeFileName):
        """
        Retrieve the HSPLs that can be used to mitigate an attack.
        @param identifier: the attack id.
        @param severity: the attack severity.
        @param attackType: the attack type.
        @param attackList: the list to parse.
        @param landscapeFileName: the name of the landscape file to parse.
        @return: The HSPL set and MSPL set that can mitigate the attack. It is
                 None if the attack is not manageable.
        @raise SyntaxError: When the generated XML is not valid.
        """

        attack = self.parser.getAttackFromList(identifier, severity, attackType,
                                               attackList)
        landscape = self.parser.getLandscape(landscapeFileName)
        recipe = self.recipesReasoner.getRecipe(attack, landscape)
        hsplSet = self.hsplReasoner.getHSPLs(attack, recipe, landscape)
        msplSet = self.msplReasoner.getMSPLs(hsplSet, landscape)

        if hsplSet is None or msplSet is None:
            return None
        else:
            return [hsplSet, msplSet]

    def listenFolder(self):
        """
        Starts the CyberTop policy engine by listening to a folder.
        """
        LOG.debug("Request for directory listening")
        directory = self.configParser.get("global", "watchedDirectory")
        LOG.debug("Starting directory listener: " + directory)
        wm = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(wm, self)
        wm.add_watch(directory, pyinotify.IN_CLOSE_WRITE, rec=True, auto_add=True)
        notifier.loop(daemonize=False)

    def send(self, hsplSet, msplSet):
        """
        Sends the policies to the dashboard.
        @param hsplSet: the HSPL set.
        @param msplSet: the MSPL set.
        """

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
                                          exchange_type="topic")
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
            LOG.debug("Dashboard RabbitMQ exchange: " + exchange + " topic: " + topic)
            LOG.info("Remediation forwarded to the dashboard")
            self.channel.close()
            LOG.info("Connection with the dashboard closed")

    def process_IN_CLOSE_WRITE(self, event):
        """
        Handles a file creation.
        @param event: The file event.
        """
        LOG.debug("Callback from event in directory")
        try:
            # First, translate the CSV in HSPL, MSPL sets
            [hsplSet, msplSet] = self.getMSPLsFromFile(event.pathname,
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
            self.send(hsplSet, msplSet)
        except BaseException as e:
            LOG.critical(str(e))
            if self.channel is not None:
                if not self.channel.is_closed:
                    self.channel.close()

    def processMessage(self, channel, method, header, body):
        """
        Handles a RabbitMQ message.
        @param channel: The channel.
        @param method: The method.
        @param header: The message header.
        @param body: The message body.
        """
        LOG.debug("Callback from event in RabbitMQ")
        line = body.decode()
        dialect = Sniffer().sniff(line)
        fields = []
        for i in reader([line], dialect):
            fields += i

        LOG.debug("DARE RabbitMQ message: " + line)
        if len(fields) == 4 and fields[0].isdigit() and match("(very\s+)?(low|high)", fields[1], IGNORECASE) and fields[3] == "start":
            identifier = int(fields[0])
            severity = " ".join(fields[1].lower().split())
            attackType = fields[2]
            LOG.info("Attack started (id: %d, severity: %s, type: %s)" % (identifier, severity, attackType))

            key = "%d-%s-%s" % (identifier, severity, attackType)
            if key in self.attacks:
                LOG.warning("Duplicate start message")
            else:
                self.attacks[key] = AttackInfo(identifier, severity, attackType)
        elif len(fields) == 4 and fields[0].isdigit() and match("(very\s+)?(low|high)", fields[1], IGNORECASE) and fields[3] == "stop":
            identifier = int(fields[0])
            severity = " ".join(fields[1].lower().split())
            attackType = fields[2]
            LOG.info("Attack stopped (id: %d, severity: %s, type: %s)" % (identifier, severity, attackType))

            key = "%d-%s-%s" % (identifier, severity, attackType)
            if key not in self.attacks:
                LOG.warning("Stop message without initial start message")
            else:
                attackInfo = self.attacks[key]
                self.attacks.pop(key)
                identifier = attackInfo.getIdentifier()
                severity = attackInfo.getSeverity()
                attackType = attackInfo.getType()
                events = attackInfo.getEvents()
                landscapeFileName = self.configParser.get("global", "landscapeFile")

                # First, translate the CSV in HSPL, MSPL sets
                [hsplSet, msplSet] = self.getMSPLsFromList(identifier, severity, attackType, events, landscapeFileName)

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
                self.send(hsplSet, msplSet)

        elif len(fields) > 4 and fields[0].isdigit() and match("(very\s+)?(low|high)", fields[1], IGNORECASE):
            identifier = int(fields[0])
            severity = " ".join(fields[1].lower().split())
            attackType = fields[2]
            LOG.debug("Attack event (id: %d, severity: %s, type: %s, body: %s)" % (identifier, severity, attackType, line))

            key = "%d-%s-%s" % (identifier, severity, attackType)
            if key not in self.attacks:
                LOG.warning("Attack event without initial start message")
            else:
                self.attacks[key].addEvent("\t".join(fields[3:]))
        else:
            LOG.warning("Unknown message format: " + line)

        #channel.basic_ack(delivery_tag=method.delivery_tag)

    def listenRabbitMQ(self):
        """
        Starts the CyberTop policy engine by listening to a RabbitMQ queue.
        @param foreground: A value stating if the daemon must be launched in foreground or background mode.
        """
        self.r_connection = self.connect()
        self.r_connection.ioloop.start()

    def stopListenRabbitMQ(self):
        self.r_closingConnection = True
        self.r_connection.ioloop.stop()
        self.r_connection.close()

    def on_connection_open(self, new_connection):
        LOG.debug('Opened connection')
        self.r_connection.add_on_close_callback(self.on_connection_closed)
        self.open_channel()

    def on_connection_closed(self, connection, reply_code, reply_text):
        LOG.debug("Detected a closed connection...reconnect in some time")
        self.r_channel = None
        if not self.r_closingConnection:
            self.r_connection.add_timeout(5, self.reconnect)
        else:
            self.r_connection.ioloop.stop()

    def on_connection_error(self, connection, error):
        LOG.debug("Connection error: " + str(error))
        time.sleep(5)
        self.reconnect()

    def reconnect(self):
        self.r_connection.ioloop.stop()
        LOG.debug("Reconnecting now")
        if not self.r_closingConnection:
            self.r_connection = self.connect()
            self.r_connection.ioloop.start()

    def open_channel(self):
        LOG.debug("Opening channel")
        self.r_connection.channel(on_open_callback=self.on_channel_open)

    def on_channel_open(self, channel):
        LOG.debug("Channel open, declaring exchange")
        exchange = self.configParser.get("global", "serverExchange")

        self.r_channel = channel
        self.r_channel.exchange_declare(self.on_exchange_declareok,
                                        exchange, "topic")

    def on_exchange_declareok(self, unused_frame):
        LOG.debug("Exchange declare is ok, declaring queue")
        queue = self.configParser.get("global", "serverQueue")
        self.r_channel.queue_declare(self.on_queue_declareok, queue, durable=True)

    def on_queue_declareok(self, frame):
        LOG.debug("Queue declare is ok, binding queue")
        queue = self.configParser.get("global", "serverQueue")
        exchange = self.configParser.get("global", "serverExchange")
        topic = self.configParser.get("global", "serverTopic")

        self.r_channel.queue_bind(self.on_bindok, queue, exchange, topic)

    def on_bindok(self, frame):
        LOG.debug("Binding queue is ok, start consuming")
        queue = self.configParser.get("global", "serverQueue")
        self.r_channel.add_on_cancel_callback(self.on_consumer_cancelled)
        self.r_channel.basic_consume(self.processMessage, queue=queue)

    def on_consumer_cancelled(self, frame):
        LOG.debug("Consumer cancelled")
        if self.r_channel:
            self.r_channel.close()

    def connect(self):
        LOG.debug("RabbitMQ connect invoked")
        address = self.configParser.get("global", "serverAddress")
        port = self.configParser.getint("global", "serverPort")
        return pika.SelectConnection(
            pika.ConnectionParameters(host=address, port=port),
            self.on_connection_open, self.on_connection_error,
            stop_ioloop_on_close=False)


class AttackInfo:
    """
    The attack information class use to perform multi-attack analysis.
    """

    def __init__(self, identifier, severity, attackType):
        """
        Creates the attack info object.
        @param identifier: the attack id.
        @param severity: the attack severity.
        @param attackType: the attack type.
        """

        self.__identifier = identifier
        if severity == "very low":
            self.__severity = 1
        elif severity == "low":
            self.__severity = 2
        elif severity == "high":
            self.__severity = 3
        else:
            self.__severity = 4
        self.__attackType = attackType
        self.__events = []

    def addEvent(self, event):
        """
        Adds an attack event.
        @param event: the event to add.
        """

        self.__events.append(event)

    def getEvents(self):
        """
        Retrieves the attack events.
        @return: the attack events.
        """

        return self.__events

    def getIdentifier(self):
        """
        Retrieves the attack identifier.
        @return: the attack identifier.
        """

        return self.__identifier

    def getSeverity(self):
        """
        Retrieves the attack severity.
        @return: the attack severity.
        """

        return self.__severity

    def getType(self):
        """
        Retrieves the attack type.
        @return: the attack type.
        """

        return self.__attackType
