"""
    Unit tests for the lisa.analysis.static_analysis module.
"""

import os
import pytest

from lisa.analysis.static_analysis import StaticAnalyzer
from lisa.core.base import AnalyzedFile


@pytest.fixture(scope='module')
def static():
    location = os.path.dirname(__file__)
    sample_path = f'{location}/../binaries/dummy_clean'
    sample = AnalyzedFile(sample_path, '/tmp')
    analyzer = StaticAnalyzer(sample)
    analyzer.run_analysis()
    return analyzer.output


def test_basic_info(static):
    assert static['binary_info']['arch'] == 'x86'
    assert static['binary_info']['endianess'] == 'little'
    assert static['binary_info']['format'] == 'elf64'
    machine = 'AMD x86-64 architecture'
    assert static['binary_info']['machine'] == machine
    assert static['binary_info']['os'] == 'linux'
    assert static['binary_info']['language'] == 'c'
    assert static['binary_info']['stripped'] is False


def test_imports(static):
    import_0 = {
        'ordinal': 1,
        'bind': 'GLOBAL',
        'type': 'FUNC',
        'name': 'recv',
        'plt': 2192
    }
    assert static['imports'][0] == import_0

    import_20 = {
        'ordinal': 21,
        'bind': 'GLOBAL',
        'type': 'FUNC',
        'name': 'socket',
        'plt': 2432
    }
    assert static['imports'][20] == import_20


def test_exports(static):
    export_0 = {
        'name': '__libc_csu_fini',
        'demname': '',
        'flagname': 'sym.__libc_csu_fini',
        'ordinal': 43,
        'bind': 'GLOBAL',
        'size': 2,
        'type': 'FUNC',
        'vaddr': 3360,
        'paddr': 3360
    }
    assert static['exports'][0] == export_0

    export_10 = {
        'name': 'main',
        'demname': '',
        'flagname': 'sym.main',
        'ordinal': 68,
        'bind': 'GLOBAL',
        'size': 513,
        'type': 'FUNC',
        'vaddr': 2730,
        'paddr': 2730
    }
    assert static['exports'][10] == export_10


def test_libs(static):
    assert len(static['libs']) == 1
    assert static['libs'][0] == 'libc.so.6'


def test_relocations(static):
    assert len(static['relocations']) == 24

    relocation_0 = {
        'name': 'N/A',
        'type': 'SET_64',
        'vaddr': 2104640,
        'paddr': 7488,
        'is_ifunc': False
    }
    assert static['relocations'][0] == relocation_0

    relocation_17 = {
        'name': 'socket',
        'type': 'SET_64',
        'vaddr': 2105296,
        'paddr': 8144,
        'is_ifunc': False
    }
    assert static['relocations'][17] == relocation_17


def test_symbols(static):
    assert len(static['symbols']) == 77

    symbol_0 = {
        'name': '.interp',
        'demname': '',
        'flagname': 'sym..interp',
        'ordinal': 1,
        'bind': 'LOCAL',
        'size': 0,
        'type': 'SECT',
        'vaddr': 568,
        'paddr': 568
    }
    assert static['symbols'][0] == symbol_0

    symbol_34 = {
        'name': 'crtstuff.c',
        'demname': '',
        'flagname': 'sym.crtstuff.c',
        'ordinal': 35,
        'bind': 'LOCAL',
        'size': 0,
        'type': 'FILE',
        'vaddr': 0,
        'paddr': 0
    }
    assert static['symbols'][34] == symbol_34

    symbol_76 = {
        'name': 'imp.socket',
        'demname': '',
        'flagname': 'sym.imp.socket',
        'ordinal': 21,
        'bind': 'GLOBAL',
        'size': 16,
        'type': 'FUNC',
        'vaddr': 2432,
        'paddr': 2432
    }
    assert static['symbols'][76] == symbol_76


def test_sections(static):
    assert len(static['sections']) == 29

    section_5 = {
        'name': '.dynsym',
        'size': 528,
        'vsize': 528,
        'perm': '-r--',
        'paddr': 696,
        'vaddr': 696
    }
    assert static['sections'][5] == section_5

    section_14 = {
        'name': '.text',
        'size': 898,
        'vsize': 898,
        'perm': '-r-x',
        'paddr': 2464,
        'vaddr': 2464
    }
    assert static['sections'][14] == section_14

    section_22 = {
        'name': '.got',
        'size': 192,
        'vsize': 192,
        'perm': '-rw-',
        'paddr': 8000,
        'vaddr': 2105152
    }
    assert static['sections'][22] == section_22
