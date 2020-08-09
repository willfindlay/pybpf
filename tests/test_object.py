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
import resource

import pytest

from pybpf.object import BPFObjectBuilder
from pybpf.utils import project_path, which

BPF_SRC = project_path('tests/bpf_src')

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


def test_bump_rlimit(builder: BPFObjectBuilder):
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (65536, 65536))

    builder.generate_skeleton(os.path.join(BPF_SRC, 'hello.bpf.c'))
    builder.set_bump_rlimit(False)
    with pytest.raises(Exception):
        builder.build()

    builder.generate_skeleton(os.path.join(BPF_SRC, 'hello.bpf.c'))
    builder.set_bump_rlimit(True)
    builder.build()


def test_autoload(builder: BPFObjectBuilder):
    builder.generate_skeleton(os.path.join(BPF_SRC, 'hello.bpf.c'))
    builder.set_autoload(False)
    obj = builder.build()
    assert obj._bpf_loaded == False
    obj.load_bpf()
    assert obj._bpf_loaded == True
    obj._cleanup()

    builder.generate_skeleton(os.path.join(BPF_SRC, 'hello.bpf.c'))
    builder.set_autoload(True)
    obj = builder.build()
    assert obj._bpf_loaded == True

