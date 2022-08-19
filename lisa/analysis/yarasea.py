"""
    YaraSea API module.
"""
import json

import requests
import logging.config

from lisa.core.base import AbstractSubAnalyzer
from lisa.config import logging_config, yarasea_url

logging.config.dictConfig(logging_config)
log = logging.getLogger()


class YaraSeaAnalyzer(AbstractSubAnalyzer):
    """Uses VirusTotal API to access finished reports.

    :param file: Analyzed file's object.
    """

    def __init__(self, file):
        super().__init__(file)
        self._yarasea_url = yarasea_url + "/upload"

    def send_to_scan(self):

        files = {'myFile': (self._file.path, open(self._file.path, 'rb'))}
        res = requests.post(self._yarasea_url, files=files)

        if res.status_code == 200:
            data = res.json()
            return data


    def run_analysis(self):
        """Main analysis method.

        :returns: Dictionary containing analysis results.
        """
        log.debug('YaraSeaAnalyzer started.')

        self._output = self.send_to_scan()

        log.debug('YaraSeaAnalyzer finished.')

        return self._output
