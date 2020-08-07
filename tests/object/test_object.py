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

    2020-Aug-05  William Findlay  Created this.
"""

import os
import time
import subprocess
import ctypes as ct

import pytest

from pybpf.object import BPFObjectBuilder
from pybpf.utils import project_path, which

BPF_SRC = project_path('tests/object/bpf_src')


@pytest.fixture
def builder(testdir):
    BPFObjectBuilder.OUTDIR = os.path.join(testdir, '.output')
    builder = BPFObjectBuilder()
    yield builder


def test_object_builder(builder: BPFObjectBuilder):
    builder._generate_vmlinux(os.path.join(BPF_SRC, 'hello.bpf.c'))
    assert os.path.exists(builder._vmlinux_kversion_h)
    assert os.path.exists(builder._vmlinux_h)
    assert builder._vmlinux_kversion_h == os.readlink(builder._vmlinux_h)

    builder._generate_bpf_obj_file(os.path.join(BPF_SRC, 'hello.bpf.c'))
    assert os.path.exists(builder._bpf_obj_file)

    builder._generate_bpf_skeleton()
    assert os.path.exists(builder._skeleton)

    builder._generate_skeleton_obj_file()
    assert os.path.exists(builder._skeleton_obj_file)

    builder.build()

def test_ringbuf(builder: BPFObjectBuilder):
    try:
        which('sleep')
    except FileNotFoundError:
        pytest.skip('sleep not found on system')

    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'ringbuf.bpf.c')).build()

    res = 0
    res2 = 0

    @obj.ringbuf_callback('ringbuf', ct.c_int)
    def _callback(ctx, data, size):
        nonlocal res
        res = data.value

    @obj.ringbuf_callback('ringbuf2', ct.c_int)
    def _callback(ctx, data, size):
        nonlocal res2
        res2 = data.value

    subprocess.check_call('sleep 1'.split())
    obj.ringbuf_consume()

    assert res == 5
    assert res2 == 10

    res = 0
    res2 = 0

    subprocess.check_call('sleep 1'.split())
    obj.ringbuf_poll(10)

    assert res == 5
    assert res2 == 10

