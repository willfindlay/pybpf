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

    Portions of this file are taken from https://github.com/iovisor/bcc/blob/master/src/python/bcc/syscall.py
    Credit and copyright goes to original authors (Sasha Goldshtein et al).
    Original bcc code was licensed under the Apache license.

    2020-Aug-02  William Findlay  Created this.
"""

import subprocess

from pybpf.utils import which, FILESYSTEMENCODING

try:
    which('ausyscall')
except FileNotFoundError:
    raise Exception('pybpf.syscalls requires the ausyscall program. Please install ausyscall.') from None

def _parse_syscall(line):
    parts = line.split()
    return (int(parts[0]), parts[1].strip().decode(FILESYSTEMENCODING))

# Taken from https://github.com/iovisor/bcc/blob/master/src/python/bcc/syscall.py
out = subprocess.check_output(['ausyscall', '--dump'], stderr=subprocess.DEVNULL)
out = out.split(b'\n',1)[1]
syscalls = dict(map(_parse_syscall, out.strip().split(b'\n')))
syscalls_rev = {v: k for k, v in syscalls.items()}

def syscall_name(syscall_num: int) -> str:
    """
    Convert a system call number to name.
    """
    return syscalls.get(syscall_num, '[unknown: {syscall_num}]')

def syscall_num(syscall_name: str) -> int:
    """
    Convert a system call name to number.
    """
    return syscalls_rev.get(syscall_name, -1)
