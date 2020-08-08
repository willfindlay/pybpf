"""
    pybpf - A BPF CO-RE (Compile Once Run Everywhere) wrapper for Python3
    Copyright (C) 2020  William Findlay

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    2020-Aug-05 William Findlay  Created this.
"""

import os
import shutil

import pytest

from pybpf.object import BPFObjectBuilder

TESTDIR = '/tmp/pybpf'

@pytest.fixture
def testdir():
    try:
        shutil.rmtree(TESTDIR)
    except FileNotFoundError:
        pass
    os.makedirs(TESTDIR)
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
