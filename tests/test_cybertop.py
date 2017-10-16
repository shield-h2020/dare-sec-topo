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
Simple tests for the CyberTop class.

@author: Daniele Canavese
"""

import sys
sys.path.append("..")

# from cybertop.cybertop import CyberTop
from cybertop.util import getHSPLNamespace
import unittest
from cybertop.cybertop import CyberTop
import os

def getTestFilePath(filename):
    """
    Retrieves a file in the test directory.
    @param filename: The file name to use.
    @return: The file path.
    """
    return os.path.join(os.path.dirname(__file__), filename)

class BasicTest(unittest.TestCase):
    """
    Basic test class.
    """

    def _doHSPLTest(self, attackFile, landscapeFile, expectedProtocols, expectedActions):
        """
        Tests the HSPL generation.
        @param attackFile: The attack file to read.
        @param landscapeFile: The CSF file to read.
        @param expectedProtocols: The expected protocol list.
        @param expectedActions: The expected actions list.
        """
        cyberTop = CyberTop(getTestFilePath("cybertop.cfg"), getTestFilePath("logging.ini"))
    
        r = cyberTop.getMSPLs(getTestFilePath(attackFile), getTestFilePath(landscapeFile))
        self.assertIsNotNone(r)
        [hsplSet, _] = r
        protocols = hsplSet.findall("{%s}hspl/{%s}traffic-constraints/{%s}type" % (getHSPLNamespace(), getHSPLNamespace(), getHSPLNamespace()))
        self.assertEqual(len(protocols), len(expectedProtocols))
        for i in range(len(protocols)):
            self.assertEqual(protocols[i].text, expectedProtocols[i])
        actions = hsplSet.findall("{%s}hspl/{%s}action" % (getHSPLNamespace(), getHSPLNamespace()))
        self.assertEqual(len(actions), len(expectedActions))
        for i in range(len(actions)):
            self.assertEqual(actions[i].text, expectedActions[i])

    def _doObjectTest(self, attackFile, landscapeFile, maximumHSPLs, expectedObjects):
        """
        Tests the HSPL generation.
        @param attackFile: The attack file to read.
        @param maximumHSPLs: The maximum number of HSPLs.
        @param landscapeFile: The CSF file to read.
        @param expectedObjects: The list of expected objects.
        """
        cyberTop = CyberTop(getTestFilePath("cybertop.cfg"), getTestFilePath("logging.ini"))
    
        r = cyberTop.getMSPLs(getTestFilePath(attackFile), getTestFilePath(landscapeFile))
        self.assertIsNotNone(r)
        [hsplSet, _] = r
        objects = hsplSet.findall("{%s}hspl/{%s}object" % (getHSPLNamespace(), getHSPLNamespace()))
        self.assertLessEqual(len(objects), maximumHSPLs)
        for i in range(len(objects)):
            self.assertIn(objects[i].text, expectedObjects)

class TestDoS(BasicTest):
    """
    Tests the DoS attack responses.
    """
        
    def test_veryHighTCP(self):
        """
        Tests the TCP flood, very high severity.
        """
        self._doHSPLTest("Very high-DoS-1.csv", "landscape1.xml", ["TCP", "TCP"], ["drop", "drop"])
        self._doHSPLTest("Very high-DoS-1.csv", "landscape2.xml", ["TCP", "TCP"], ["drop", "drop"])
        
    def test_highTCP(self):
        """
        Tests the TCP flood, high severity.
        """
        self._doHSPLTest("High-DoS-1.csv", "landscape1.xml", ["TCP", "TCP"], ["drop", "drop"])
        self._doHSPLTest("High-DoS-1.csv", "landscape2.xml", ["TCP", "TCP"], ["drop", "drop"])
    
    def test_lowTCP(self):
        """
        Tests the TCP flood, low severity.
        """
        self._doHSPLTest("Low-DoS-1.csv", "landscape1.xml", ["TCP", "TCP"], ["limit", "limit"])
        self._doHSPLTest("Low-DoS-1.csv", "landscape2.xml", ["TCP", "TCP"], ["drop", "drop"])

    def test_veryLowTCP(self):
        """
        Tests the TCP flood, low severity.
        """
        self._doHSPLTest("Very low-DoS-1.csv", "landscape1.xml", ["TCP", "TCP"], ["limit", "limit"])
        self._doHSPLTest("Very low-DoS-1.csv", "landscape2.xml", ["TCP", "TCP"], ["drop", "drop"])

    def test_veryHighUDP(self):
        """
        Tests the UDP flood, very high severity.
        """
        self._doHSPLTest("Very high-DoS-2.csv", "landscape1.xml", ["UDP", "UDP"], ["drop", "drop"])
        self._doHSPLTest("Very high-DoS-2.csv", "landscape2.xml", ["UDP", "UDP"], ["drop", "drop"])
        
    def test_highUDP(self):
        """
        Tests the UDP flood, high severity.
        """
        self._doHSPLTest("High-DoS-2.csv", "landscape1.xml", ["UDP", "UDP"], ["drop", "drop"])
        self._doHSPLTest("High-DoS-2.csv", "landscape2.xml", ["UDP", "UDP"], ["drop", "drop"])

    def test_lowUDP(self):
        """
        Tests the TCP flood, low severity.
        """
        self._doHSPLTest("Low-DoS-2.csv", "landscape1.xml", ["UDP", "UDP"], ["limit", "limit"])
        self._doHSPLTest("Low-DoS-2.csv", "landscape2.xml", ["UDP", "UDP"], ["drop", "drop"])

    def test_veryLowUDP(self):
        """
        Tests the TCP flood, low severity.
        """
        self._doHSPLTest("Very low-DoS-2.csv", "landscape1.xml", ["UDP", "UDP"], ["limit", "limit"])
        self._doHSPLTest("Very low-DoS-2.csv", "landscape2.xml", ["UDP", "UDP"], ["drop", "drop"])

    def test_VeryHighTCPAndUDP(self):
        """
        Tests the UDP flood, very high severity.
        """
        self._doHSPLTest("Very high-DoS-3.csv", "landscape1.xml", ["TCP", "UDP"], ["drop", "drop"])
        self._doHSPLTest("Very high-DoS-3.csv", "landscape2.xml", ["TCP", "UDP"], ["drop", "drop"])

    def test_highTCPAndUDP(self):
        """
        Tests the UDP flood, high severity.
        """
        self._doHSPLTest("High-DoS-3.csv", "landscape1.xml", ["TCP", "UDP"], ["drop", "drop"])
        self._doHSPLTest("High-DoS-3.csv", "landscape2.xml", ["TCP", "UDP"], ["drop", "drop"])

    def test_lowTCPAndUDP(self):
        """
        Tests the UDP flood, high severity.
        """
        self._doHSPLTest("Low-DoS-3.csv", "landscape1.xml", ["TCP", "UDP"], ["limit", "limit"])
        self._doHSPLTest("Low-DoS-3.csv", "landscape2.xml", ["TCP", "UDP"], ["drop", "drop"])

    def test_veryLowTCPAndUDP(self):
        """
        Tests the UDP flood, high severity.
        """
        self._doHSPLTest("Very low-DoS-3.csv", "landscape1.xml", ["TCP", "UDP"], ["limit", "limit"])
        self._doHSPLTest("Very low-DoS-3.csv", "landscape2.xml", ["TCP", "UDP"], ["drop", "drop"])

class TestDNSTunneling(BasicTest):
    """
    Tests the DNS tunneling attack responses.
    """
        
    def test_veryHighDNS(self):
        """
        Tests the DNS tunneling, very high severity.
        """
        self._doHSPLTest("Very high-DNS tunneling-1.csv", "landscape1.xml", ["TCP+UDP"], ["drop"])
        self._doHSPLTest("Very high-DNS tunneling-1.csv", "landscape2.xml", ["TCP+UDP"], ["drop"])
        
    def test_highDNS(self):
        """
        Tests the DNS tunneling, very high severity.
        """
        self._doHSPLTest("High-DNS tunneling-1.csv", "landscape1.xml", ["TCP+UDP"], ["drop"])
        self._doHSPLTest("High-DNS tunneling-1.csv", "landscape2.xml", ["TCP+UDP"], ["drop"])
        
    def test_lowDNS(self):
        """
        Tests the DNS tunneling, very high severity.
        """
        self._doHSPLTest("Low-DNS tunneling-1.csv", "landscape1.xml", ["TCP+UDP"], ["drop"])
        self._doHSPLTest("Low-DNS tunneling-1.csv", "landscape2.xml", ["TCP+UDP"], ["drop"])
        
    def test_veryLowDNS(self):
        """
        Tests the DNS tunneling, very high severity.
        """
        self._doHSPLTest("Very low-DNS tunneling-1.csv", "landscape1.xml", ["TCP+UDP"], ["drop"])
        self._doHSPLTest("Very low-DNS tunneling-1.csv", "landscape2.xml", ["TCP+UDP"], ["drop"])

    def test_noneDNS(self):
        """
        Tests the DNS tunneling, no severity.
        """
        self._doHSPLTest("dns_results.csv", "landscape1.xml", ["TCP+UDP"] * 2, ["drop"] * 2)
        self._doHSPLTest("dns_results.csv", "landscape2.xml", ["TCP+UDP"] * 2, ["drop"] * 2)

class TestHSPLMerging(BasicTest):
    """
    Tests the HSPL merging.
    """

    def test_mergeAnyPorts(self):
        """
        Tests that any ports merging.
        """
        self._doObjectTest("Very low-DoS-4.csv", "landscape1.xml", 10, ["91.211.1.100:*"])

    def test_mergeSubnets(self):
        """
        Tests the subnets merging.
        """
        self._doObjectTest("Very low-DoS-5.csv", "landscape1.xml", 10, [
            "91.211.1.0/31:*",
            "91.211.1.2/31:*",
            "91.211.1.4/31:*",
            "91.211.1.6/31:*",
            "91.211.1.8/31:*",
            "91.211.1.10/31:*"])
    def test_mergeAnyPortsWithInclusions(self):
        """
        Tests that any ports merging with some inclusions.
        """
        self._doObjectTest("Very low-DoS-6.csv", "landscape1.xml", 10, ["91.211.1.0:*"])

    def test_mergeSubnetsWithInclusions(self):
        """
        Tests the subnets merging with some inclusions.
        """
        self._doObjectTest("Very low-DoS-7.csv", "landscape1.xml", 10, [
            "91.211.1.0/31:*",
            "91.211.1.2/31:*",
            "91.211.1.4/31:*",
            "91.211.1.6/31:*",
            "91.211.1.8/31:*",
            "91.211.1.10/31:*"])

    def test_mergeAll(self):
        """
        Tests the any ports and subnets merging with some inclusions.
        """
        self._doObjectTest("Very low-DoS-8.csv", "landscape1.xml", 10, [
            "91.211.1.0/31:*",
            "91.211.1.2/31:*",
            "91.211.1.4/31:*",
            "91.211.1.6/31:*",
            "91.211.1.8/31:*",
            "91.211.1.10/31:*"])

    def test_mergeBig1(self):
        """
        Big test #1!
        """
        self._doObjectTest("Very low-DoS-9.csv", "landscape1.xml", 10, [
            "1.100.7.0/25:*",
            "1.100.7.128/25:*",
            "1.152.233.0/25:*",
            "1.152.233.128/25:*",
            "10.14.254.0/25:*",
            "10.14.254.128/25:*",
            "10.101.30.61:*",
            "100.114.244.0/25:*",
            "100.114.244.128/25:*"])

    def test_mergeBig2(self):
        """
        Big test #2!
        """
        self._doObjectTest("Very low-DoS-10.csv", "landscape1.xml", 10, ["1.2.3.4:*"])

    def test_mergeBig3(self):
        """
        Big test #3!
        """
        self._doObjectTest("Very low-DoS-11.csv", "landscape1.xml", 10, ["1.2.3.4:*", "1.2.3.5:*"])

    def test_mergeBig4(self):
        """
        Big test #4!
        """
        self._doObjectTest("Very low-DoS-12.csv", "landscape1.xml", 10, [
            "1.2.3.0/27:*",
            "1.2.3.32/27:*",
            "1.2.3.64/27:*",
            "1.2.3.96/27:*",
            "1.2.3.128/27:*",
            "1.2.3.160/27:*",
            "1.2.3.192/27:*",
            "1.2.3.224/27:*"])

    def test_mergeBig5(self):
        """
        Big test #5!
        """
        self._doObjectTest("Very low-DoS-13.csv", "landscape1.xml", 16, [
            "1.0.0.0/24:*",
            "1.0.50.0/24:*",
            "1.0.100.0/24:*",
            "1.0.150.0/24:*",
            "1.1.0.0/24:*",
            "1.1.50.0/24:*",
            "1.1.100.0/24:*",
            "1.1.150.0/24:*",
            "1.2.0.0/24:*",
            "1.2.50.0/24:*",
            "1.2.100.0/24:*",
            "1.2.150.0/24:*",
            "1.3.0.0/24:*",
            "1.3.50.0/24:*",
            "1.3.100.0/24:*",
            "1.3.150.0/24:*"])

if __name__ == "__main__":
    unittest.main()
