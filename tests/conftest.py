"""
    pybpf - A BPF CO-RE (Compile Once Run Everywhere) wrapper for Python3
    Copyright (C) 2020  William Findlay

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
    USA

    2020-Aug-05 William Findlay  Created this.
"""

import os
import shutil

import pytest

from pybpf.utils import drop_privileges
from pybpf.object import BPFObjectBuilder

TESTDIR = '/tmp/pybpf'

@drop_privileges
def make_testdir():
    os.makedirs(TESTDIR)

@pytest.fixture
def testdir():
    try:
        shutil.rmtree(TESTDIR)
    except FileNotFoundError:
        pass
    make_testdir()
    yield TESTDIR


@pytest.fixture
def builder(testdir):
    BPFObjectBuilder.OUTDIR = os.path.join(testdir, '.output')
    builder = BPFObjectBuilder()
    yield builder
    try:
        builder.bpf_object._cleanup()
    except Exception:
        pass
