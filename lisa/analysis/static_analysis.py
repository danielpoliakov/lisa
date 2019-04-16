"""
    Static analysis module.
"""

import r2pipe
import subprocess
import logging.config

from lisa.core.base import AbstractSubAnalyzer
from lisa.config import logging_config

logging.config.dictConfig(logging_config)
log = logging.getLogger()


class StaticAnalyzer(AbstractSubAnalyzer):
    """Provides static analysis.

    :param file: Analyzed file's object.
    """

    def run_analysis(self):
        """Main analysis method.

        :returns: Dictionary containing analysis results.
        """
        log.info('Static Analysis started.')

        # start radare2
        self._r2 = r2pipe.open(self._file.path, ['-2'])
        self._r2.cmd('aaa')

        # binary info
        self._r2_info()

        # strings
        self._load_strings()

        self._r2.quit()
        log.info('Static Analysis finished.')

        return self._output

    def _r2_info(self):
        """Basic binary information from r2 tool."""
        info = self._r2.cmdj('ij')
        entry_point = self._r2.cmdj('iej')

        info_select = {
            'arch': info['bin']['arch'],
            'endianess': info['bin']['endian'],
            'format': info['core']['format'],
            'machine': info['bin']['machine'],
            'type': info['core']['type'],
            'size': info['core']['size'],
            'os': info['bin']['os'],
            'static': info['bin']['static'],
            'interpret': info['bin']['intrp'],
            'language': info['bin']['lang'],
            'stripped': info['bin']['stripped'],
            'relocations': info['bin']['relocs'],
            'min_opsize': info['bin']['minopsz'],
            'max_opsize': info['bin']['maxopsz'],
            'entry_point': entry_point[0]['vaddr']
        }

        imports = self._r2.cmdj('iij')
        exports = self._r2.cmdj('iEj')
        libs = self._r2.cmdj('ilj')
        relocations = self._r2.cmdj('irj')
        symbols = self._r2.cmdj('isj')
        sections = self._r2.cmdj('iSj')

        self._output['binary_info'] = info_select
        self._output['imports'] = imports
        self._output['exports'] = exports
        self._output['libs'] = libs
        self._output['relocations'] = relocations
        self._output['symbols'] = symbols
        self._output['sections'] = sections

    def _load_strings(self):
        """Returns list of printable strings contained in binary.
        Uses standard linux tool `strings`.

        :param file_path: Path to file.
        """
        p = subprocess.Popen(['strings', self._file.path],
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        out = p.communicate()[0]
        strings_list = out.splitlines()

        self._output['strings'] = strings_list
