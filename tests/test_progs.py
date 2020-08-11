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

    2020-Aug-11  William Findlay  Created this.
"""

import os
import time
import subprocess
import ctypes as ct

import pytest

from pybpf.object import BPFObjectBuilder
from pybpf.maps import create_map
from pybpf.utils import project_path, which

BPF_SRC = project_path('tests/bpf_src')

def test_progs_smoke(builder: BPFObjectBuilder):
    """
    Make sure progs load properly.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'prog.bpf.c')).build()

    EXPECTED_PROG_COUNT = 4

    if len(obj._progs) > EXPECTED_PROG_COUNT:
        pytest.xfail(f'EXPECTED_PROG_COUNT should be updated to {len(obj._progs)}')

    assert len(obj._progs) == EXPECTED_PROG_COUNT

def test_bad_prog(builder: BPFObjectBuilder):
    """
    Test that accessing a non-existent prog raises a KeyError.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'prog.bpf.c')).build()

    with pytest.raises(KeyError):
        obj.prog('foo')

def test_prog_invoke(builder: BPFObjectBuilder):
    """
    Test .invoke() method on supported program types.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'prog.bpf.c')).build()

    fexit_modify_return_test = obj.prog('fexit_modify_return_test')
    assert fexit_modify_return_test.invoke() == 0

    fentry_modify_return_test = obj.prog('fentry_modify_return_test')
    assert fentry_modify_return_test.invoke() == 0
