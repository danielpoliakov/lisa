"""
    Base module - holding abstract classes and common structures.
"""

import os
import subprocess

from datetime import datetime
from abc import ABC, abstractmethod
from lisa.core.architecture import get_architecture


def get_checksum(file_path, sum_type):
    """Returns md5, sha1 or sha256 checksum. Uses standard
    linux tools - [md5|sha1|sha256]sum.

    :param file_path: Path to file.
    :param sum_type: Type of checksum (md5 / sha1 / sha256)
    :returns: String containing calculated checksum.
    """
    p = subprocess.Popen([sum_type + 'sum', file_path],
                         stdout=subprocess.PIPE,
                         universal_newlines=True)
    out = p.communicate()[0]
    checksum = out.split()[0]
    return checksum


class AbstractSubAnalyzer(ABC):
    """Abstract base class for sub-analyzers.

    :param file: AnalyzedFile's object.
    """

    def __init__(self, file):
        self._file = file
        self._output = {}

    @abstractmethod
    def run_analysis(self):
        raise NotImplementedError

    @property
    def file(self):
        """Analyzed file."""
        return self._file

    @property
    def output(self):
        """Analysis output."""
        return self._output


class AnalyzedFile():
    """Class for holding analyzed samples information.

    :param file_path: Path to analyzed file.
    :param data: Path to analysis data folder.
    :param exec_time: Execution time for behavioral modules.
    """

    def __init__(self, file_path, data_dir, exec_time=20):
        self._path = os.path.abspath(file_path)
        self._name = os.path.basename(file_path)
        self._dir = os.path.dirname(self._path)
        self._data_dir = data_dir
        self._exec_time = exec_time

        # get architecture info
        arch_info = get_architecture(file_path)
        self._arch, self._bit, self._endian = arch_info

        self.md5 = get_checksum(self._path, 'md5')

        # initial output preparation
        self._output = {
            'file_name': self._name,
            'type': 'binary',
            'exec_time': self._exec_time,
            'timestamp': datetime.now().strftime(
                '%Y-%m-%d %H:%M'
            ),
            'md5': self.md5,
            'sha1': get_checksum(self._path, 'sha1'),
            'sha256': get_checksum(self._path, 'sha256')
        }

    @property
    def arch(self):
        """Architecture (e.g. mips)"""
        return self._arch

    @property
    def bit(self):
        """Bit (32 x 64)"""
        return self._bit

    @property
    def endian(self):
        """Endianness (little x big)"""
        return self._endian

    @property
    def name(self):
        """File name."""
        return self._name

    @property
    def path(self):
        """Full file path."""
        return self._path

    @property
    def dir(self):
        """Files directory."""
        return self._dir

    @property
    def output(self):
        """Analysis output."""
        return self._output

    @property
    def data_dir(self):
        """Analysis data dir path."""
        return self._data_dir

    @property
    def exec_time(self):
        """Execution time for behavioral modules."""
        return self._exec_time


class AnalyzedPcap():
    """Class for holding analyzed pcap information.

    :param pcap_path: Path to pcap.
    """

    def __init__(self, pcap_path):
        self._path = os.path.abspath(pcap_path)
        self._name = os.path.basename(pcap_path)
        self._dir = os.path.dirname(self._path)

        self._output = {
            'file_name': self._name,
            'type': 'pcap',
            'timestamp': datetime.now().strftime(
                '%Y-%m-%d %H:%M'
            ),
        }

    @property
    def name(self):
        """Pcap filename."""
        return self._name

    @property
    def path(self):
        """Full pcap path."""
        return self._path

    @property
    def dir(self):
        """Pcap directory."""
        return self._dir

    @property
    def output(self):
        """Analysis output."""
        return self._output
