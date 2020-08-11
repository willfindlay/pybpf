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

    2020-Aug-05  William Findlay  Created this.
"""

import os
import time
import subprocess
import ctypes as ct
import resource

import pytest

from pybpf.project_init import ProjectInit
from pybpf.utils import project_path, which

BPF_SRC = project_path('tests/bpf_src')

#def test_object_init(init: ProjectInit):
#    """
#    Test each component of the object init.
#    """
#    init._generate_vmlinux(os.path.join(BPF_SRC, 'hello.bpf.c'))
#    assert os.path.exists(init._vmlinux_kversion_h)
#    assert os.path.exists(init._vmlinux_h)
#    assert init._vmlinux_kversion_h == os.readlink(init._vmlinux_h)
#
#    init._generate_bpf_obj_file(os.path.join(BPF_SRC, 'hello.bpf.c'))
#    assert os.path.exists(init._bpf_obj_file)
#
#    init._generate_bpf_skeleton()
#    assert os.path.exists(init._skeleton)
#
#    init._compile_bpf_skeleton_obj_file()
#    assert os.path.exists(init._skeleton_obj_file)
#
#    init


#def test_bump_rlimit(init: ProjectInit):
#    """
#    Test turning bump_rlimit off.
#    """
#    resource.setrlimit(resource.RLIMIT_MEMLOCK, (65536, 65536))
#
#    init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'hello.bpf.c'))
#    init.set_bump_rlimit(False)
#    with pytest.raises(Exception):
#        init
#
#    init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'hello.bpf.c'))
#    init.set_bump_rlimit(True)
#    init
#
#
#def test_autoload(init: ProjectInit):
#    """
#    Test turning autoload off.
#    """
#    init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'hello.bpf.c'))
#    init.set_autoload(False)
#    obj = init
#    assert obj._bpf_loaded == False
#    obj.load_bpf()
#    assert obj._bpf_loaded == True
#    obj._cleanup()
#
#    init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'hello.bpf.c'))
#    init.set_autoload(True)
#    obj = init
#    assert obj._bpf_loaded == True
#
