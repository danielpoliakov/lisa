"""
    Unit tests for full run_analysis with QEMU emulation.
"""

import os
import pytest

from lisa.analysis.dynamic_analysis import DynamicAnalyzer
from lisa.core.base import AnalyzedFile

location = os.path.dirname(__file__)


@pytest.fixture(scope='module')
def analysis():
    return {'output': None}


def test_run_analysis(analysis):
    sample_path = f'{location}/../binaries/testbin-puts-arm'
    sample = AnalyzedFile(sample_path, '/tmp')
    analyzer = DynamicAnalyzer(sample)
    analyzer.run_analysis()
    analysis['output'] = analyzer.output


def test_syscalls_correct(analysis):
    syscall_0 = analysis['output']['syscalls'][0]
    assert syscall_0['name'] == 'brk'

    syscall_write = analysis['output']['syscalls'][-2]
    assert syscall_write['name'] == 'write'

    write_args = syscall_write['arguments']
    assert write_args.startswith('1, "LiSa test.')


def test_pcap_correct(analysis):
    pcap_size = os.path.getsize('/tmp/capture.pcap')
    assert pcap_size != 0
