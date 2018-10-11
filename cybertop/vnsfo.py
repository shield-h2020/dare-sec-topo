# Copyright 2018 Politecnico di Torino
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
import requests
from cybertop.log import LOG


def retrieve_vnsfr_id(vnsfo_base_url, vnfd_id, attack_name, timeout):
    LOG.info("Request vNSFO API call for vnsfd_id=" + vnfd_id +
             " and attack type=" + attack_name)
    url = vnsfo_base_url + "/vnsf/running"
    LOG.info("VNSFO API call: " + url)

    try:
        response = requests.get(url, verify=False, timeout=timeout)
        LOG.info("VNSFO API response: " + response.text)
        vnsfs = response.json()["vnsf"]

        # search for first running instance which matches the query
        for vnsf in vnsfs:
            if vnsf['vnfd_id'] == vnfd_id:
                LOG.info("Found running vNSF with matching vnfd_id")
                if attack_name.lower() in vnsf['ns_name'].lower():
                    LOG.info("Found instance=" + vnsf['vnfr_id'] +
                             " for attack=" + attack_name)
                    return vnsf['vnfr_id']
        LOG.info("No running instance found from VNSFO API.")
        return None
    except Exception as e:
        LOG.critical("VNSFO API error: " + str(e))
        return None
