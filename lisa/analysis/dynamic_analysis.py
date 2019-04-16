"""
    Dynamic analysis module.
"""

import logging.config

from lisa.core.base import AbstractSubAnalyzer
from lisa.core.qemu_guest import QEMUGuest
from lisa.config import logging_config

logging.config.dictConfig(logging_config)
log = logging.getLogger()


class DynamicAnalyzer(AbstractSubAnalyzer):
    """Provides dynamic analysis.

    :param file: AnalyzedFile's object.
    """

    def __init__(self, file):
        super().__init__(file)
        self._syscalls = []
        self._files = []
        self._processes = []

    def run_analysis(self):
        """Main analysis method.

        :returns: Dictionary containing analysis results.
        """
        log.info('Dynamic Analysis started.')

        # start vm
        self._vm = QEMUGuest(self._file)
        self._vm.start_vm()

        if not self._vm.is_running:
            log.critical('Error running VM.')
            return

        self._vm.run_and_analyze(self._file.exec_time)

        self._vm.poweroff_vm()

        self._vm.extract_output()

        self._analyze_behavior(f'{self._file.data_dir}/behav.out')

        log.info('Dynamic Analysis finished.')

        self._output['syscalls'] = self._syscalls
        self._output['open_files'] = self._files
        self._output['processes'] = self._processes

        return self._output

    def _analyze_behavior(self, behav_file):
        """Extracts behavioral data from behav.out file
        captured by lisa systemtap module.

        :param behav_file: behav.out file path.
        """
        started = False

        with open(behav_file) as f:
            line = f.readline()
            while line:
                if line.startswith('SYSCALL'):
                    syscall = {
                        'execname': f.readline()[:-1],
                        'name': f.readline()[:-1],
                        'pid': f.readline()[:-1],
                        'arguments': f.readline()[:-1],
                        'return': f.readline()[:-1]
                    }

                    # ommit initial execve from help process
                    if started:
                        self._syscalls.append(syscall)
                    else:
                        started = True

                if line.startswith('PROCESS'):
                    inner = f.readline()
                    if not inner:
                        break

                    pid, pid_parent = inner.strip().split(':')
                    process = {
                        'pid': int(pid),
                        'parent': int(pid_parent)
                    }
                    self._processes.append(process)

                if line.startswith('OPENFILE'):
                    inner = f.readline()
                    if not inner:
                        break

                    file = inner.strip('"\n')
                    self._files.append(file)

                line = f.readline()
