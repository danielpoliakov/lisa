"""
    Unit tests for syscall extraction.
"""

import os
import pytest

from lisa.analysis.dynamic_analysis import DynamicAnalyzer


@pytest.fixture(scope='module')
def syscalls():
    analyzer = DynamicAnalyzer(None)
    location = os.path.dirname(__file__)
    behav_file = f'{location}/behav.out'
    analyzer._analyze_behavior(behav_file)
    return analyzer._syscalls


def test_syscalls_group_1(syscalls):
    assert len(syscalls) == 48

    assert syscalls[0] == {
        'execname': 'analyzed_bin',
        'name': 'brk',
        'pid': '109',
        'arguments': '0x0',
        'return': '4464640'
    }

    assert syscalls[5] == {
        'execname': 'analyzed_bin',
        'name': 'openat',
        'pid': '109',
        'arguments': ('AT_FDCWD, "/lib/tls/i686/libc.so.6", '
                      'O_RDONLY|O_LARGEFILE|O_CLOEXEC'),
        'return': '-2 (ENOENT)'
    }

    assert syscalls[25] == {
        'execname': 'analyzed_bin',
        'name': 'close',
        'pid': '109',
        'arguments': '3',
        'return': '0'
    }

    assert syscalls[34] == {
        'execname': 'analyzed_bin',
        'name': 'fstat',
        'pid': '109',
        'arguments': '3, 0xffffffffbf863680',
        'return': '0'
    }

    assert syscalls[47] == {
        'execname': 'analyzed_bin',
        'name': 'exit_group',
        'pid': '109',
        'arguments': '0',
        'return': ''
    }
