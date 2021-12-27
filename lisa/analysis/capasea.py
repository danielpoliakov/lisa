"""
    CapaSea API module.
"""
import json

import requests
import logging.config

from lisa.core.base import AbstractSubAnalyzer
from lisa.config import logging_config, capasea_url

logging.config.dictConfig(logging_config)
log = logging.getLogger()


class CapaaSeaAnalyzer(AbstractSubAnalyzer):

    def __init__(self, file):
        super().__init__(file)
        self._capasea_url = capasea_url + "/upload"


    def send_to_scan(self):

        files = {'myFile': (self._file.path, open(self._file.path, 'rb'))}
        res = requests.post(self._capasea_url, files=files)

        if res.status_code == 200:
            data = res.json()
            return data

    def wait_for_results(self, report_url_json):
        loop_check = True
        report_url = json.loads(report_url_json)
        url_check = capasea_url + report_url["report"][1:]
        while loop_check:
            res = requests.get(url_check)
            if len(res.text) != 0:
                loop_check = False
                json_return = '{"capa_report":"' + res.text + '"}'
        return json_return


    def run_analysis(self):
        """Main analysis method.

        :returns: Dictionary containing analysis results.
        """
        log.debug('CapaSeaAnalyzer started.')

        report_url = self.send_to_scan()

        self._output = self.wait_for_results(report_url)

        log.debug('CapaSeaAnalyzer finished.')

        return self._output
