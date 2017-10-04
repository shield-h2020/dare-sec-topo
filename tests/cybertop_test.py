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
Basic tests for the CyberTop class.

:author: Daniele Canavese
"""

import sys
sys.path.append("../src")

from cybertop.cybertop import CyberTop
import unittest

import os

def get_test_data_path(filename):
    """
    Retrieves the test data path
    """
    return os.path.join(os.path.dirname(__file__), filename)


class BasicTest(unittest.TestCase):
    """
    Tests the basic capabilities of the tool.
    """

    # The HSPL namespace.
    NAMESPACE_HSPL = "http://security.polito.it/shield/hspl"
    
    def testTCPFloodLowSeverity(self):
        """
        Tests the TCP flood, low severity.
        """
        cyberTop = CyberTop(
            get_test_data_path('cybertop.cfg'),
            get_test_data_path('logging.ini')
        )

        # Chooses limit.        
        [hsplSet, msplSet] = cyberTop.getMSPLs(
            get_test_data_path("1-TCP flood-123.csv"),
            get_test_data_path("landscape1.xml"))  # @UnusedVariable
        
        actions = hsplSet.findall("{%s}hspl/{%s}action" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        
        for i in actions:
            self.assertEqual(i.text, "limit")

        # Chooses drop.        
        
        [hsplSet, msplSet] = cyberTop.getMSPLs(
            get_test_data_path("1-TCP flood-123.csv"),
            get_test_data_path("landscape2.xml"))  # @UnusedVariable
        
        actions = hsplSet.findall("{%s}hspl/{%s}action" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        
        for i in actions:
            self.assertEqual(i.text, "drop")
    
    def testTCPFloodHighSeverity(self):
        """
        Tests the TCP flood, high severity.
        """
        cyberTop = CyberTop(
            get_test_data_path('cybertop.cfg'),
            get_test_data_path('logging.ini')
        )

        # Chooses drop.        
        [hsplSet, msplSet] = cyberTop.getMSPLs(
            get_test_data_path("3-TCP flood-125.csv"),
            get_test_data_path("landscape1.xml"))  # @UnusedVariable
        actions = hsplSet.findall("{%s}hspl/{%s}action" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        for i in actions:
            self.assertEqual(i.text, "drop")

        # Chooses drop.        
        [hsplSet, msplSet] = cyberTop.getMSPLs(
            get_test_data_path("3-TCP flood-125.csv"),
            get_test_data_path("landscape2.xml"))  # @UnusedVariable
        actions = hsplSet.findall("{%s}hspl/{%s}action" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        for i in actions:
            self.assertEqual(i.text, "drop")
        
    def testUDPFloodLowSeverity(self):
        """
        Tests the UDP flood, low severity.
        """
        cyberTop = CyberTop(
            get_test_data_path('cybertop.cfg'),
            get_test_data_path('logging.ini')
        )

        # Chooses limit.        
        [hsplSet, msplSet] = cyberTop.getMSPLs(
            get_test_data_path("1-UDP flood-124.csv"),
            get_test_data_path("landscape1.xml"))  # @UnusedVariable
        actions = hsplSet.findall("{%s}hspl/{%s}action" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        for i in actions:
            self.assertEqual(i.text, "limit")

        # Chooses drop.        
        [hsplSet, msplSet] = cyberTop.getMSPLs(
            get_test_data_path("1-UDP flood-124.csv"),
            get_test_data_path("landscape2.xml"))  # @UnusedVariable
        actions = hsplSet.findall("{%s}hspl/{%s}action" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        for i in actions:
            self.assertEqual(i.text, "drop")
    
    def testUDPFloodHighSeverity(self):
        """
        Tests the UDP flood, high severity.
        """
        cyberTop = CyberTop(
            get_test_data_path('cybertop.cfg'),
            get_test_data_path('logging.ini')
        )

        # Chooses drop.        
        [hsplSet, msplSet] = cyberTop.getMSPLs(
            get_test_data_path("3-UDP flood-126.csv"),
            get_test_data_path("landscape1.xml"))  # @UnusedVariable
        actions = hsplSet.findall("{%s}hspl/{%s}action" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        for i in actions:
            self.assertEqual(i.text, "drop")

        # Chooses drop.        
        [hsplSet, msplSet] = cyberTop.getMSPLs(
            get_test_data_path("3-UDP flood-126.csv"),
            get_test_data_path("landscape2.xml"))  # @UnusedVariable
        actions = hsplSet.findall("{%s}hspl/{%s}action" % (self.NAMESPACE_HSPL, self.NAMESPACE_HSPL))
        for i in actions:
            self.assertEqual(i.text, "drop")

if __name__ == "__main__":
    unittest.main()
