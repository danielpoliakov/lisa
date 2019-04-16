"""
    Unit tests for process tree extraction from behav.out file.
"""

import os
import pytest

from lisa.analysis.dynamic_analysis import DynamicAnalyzer


@pytest.fixture(scope='module')
def processes():
    analyzer = DynamicAnalyzer(None)
    location = os.path.dirname(__file__)
    behav_file = f'{location}/behav.out'
    analyzer._analyze_behavior(behav_file)
    return analyzer._processes


def test_files_extract(processes):
    assert processes[0]['pid'] == 109
    assert processes[0]['parent'] == 105
    assert processes[1]['pid'] == 111
    assert processes[1]['parent'] == 109
