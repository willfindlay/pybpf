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
import sys
import shutil

import pytest

from pybpf.bootstrap import Bootstrap
from pybpf.skeleton import generate_skeleton
from pybpf.utils import drop_privileges

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
def skeleton(testdir):
    import importlib.util
    def _do_skeleton(bpf_src: str, *args, **kwargs):
        skel_file, skel_cls = Bootstrap.bootstrap(bpf_src=bpf_src, outdir=testdir)
        d, f = os.path.split(skel_file)
        spec = importlib.util.spec_from_file_location(f'{skel_cls}', skel_file)
        skel_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(skel_mod)
        return getattr(skel_mod, skel_cls)(*args, **kwargs)
    yield _do_skeleton
