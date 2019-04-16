"""
    Unit tests for opened files extraction from behav.out file.
"""

import os
import pytest

from lisa.analysis.dynamic_analysis import DynamicAnalyzer


@pytest.fixture(scope='module')
def files():
    analyzer = DynamicAnalyzer(None)
    location = os.path.dirname(__file__)
    behav_file = f'{location}/behav.out'
    analyzer._analyze_behavior(behav_file)
    return analyzer._files


def test_files_extract(files):
    assert files[0] == '/etc/ld.so.cache'
    assert files[1] == '/lib/tls/i686/sse2/libc.so.6'
    assert files[2] == '/lib/tls/i686/libc.so.6'
    assert files[3] == '/lib/tls/sse2/libc.so.6'
    assert files[4] == '/lib/tls/libc.so.6'
    assert files[5] == '/lib/i686/sse2/libc.so.6'
    assert files[6] == '/lib/i686/libc.so.6'
    assert files[7] == '/lib/sse2/libc.so.6'
    assert files[8] == '/lib/libc.so.6'
    assert files[9] == '/etc/passwd'
