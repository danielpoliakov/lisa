"""
    VirusTotal API module.
"""

import requests
import logging.config

from lisa.core.base import AbstractSubAnalyzer
from lisa.config import logging_config, virus_total_key

logging.config.dictConfig(logging_config)
log = logging.getLogger()


class VirusTotalAnalyzer(AbstractSubAnalyzer):
    """Uses VirusTotal API to access finished reports.

    :param file: Analyzed file's object.
    """

    def __init__(self, file):
        super().__init__(file)
        self._scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        self._reports_url = 'https://www.virustotal.com/vtapi/v2/file/report'
        self._api_key = virus_total_key

    def send_to_scan(self):
        """Send file to VirusTotal scan.

        :returns: VT response code.
        """
        attr = {'apikey': self._api_key}
        files = {'file': open(self._file.path, 'rb')}
        res = requests.post(self._scan_url, data=attr, files=files)

        if res.status_code == 200:
            data = res.json()
            self._md5 = data['md5']
            return data['response_code']

    def retrieve_report(self):
        """Get scan results from VirusTotal.

        :returns: Dictionary containing report.
        """
        attr = {'apikey': self._api_key, 'resource': self._file.md5}
        res = requests.post(self._reports_url, data=attr)

        if res.status_code == 200:
            return res.json()
        else:
            return {'error': 'Can\'t retrieve reponse from VirusTotal.'}

    def run_analysis(self):
        """Main analysis method.

        :returns: Dictionary containing analysis results.
        """
        log.debug('VirusTotalAnalyzer started.')

        self._output = self.retrieve_report()

        log.debug('VirusTotalAnalyzer finished.')

        return self._output
