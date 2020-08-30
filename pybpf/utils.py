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

    2020-Aug-02  William Findlay  Created this.
"""

import os
import sys
import re
import subprocess
import platform
from enum import IntEnum, auto
from ctypes import get_errno
from typing import Union, Optional


def module_path(pathname: str) -> str:
    """
    Get path to a file from the root directory of this module.
    """
    return os.path.realpath(os.path.join(os.path.dirname(__file__), pathname))


def project_path(pathname: str) -> str:
    """
    Get path to a file from the root directory of this project.
    """
    return os.path.realpath(
        os.path.join(os.path.dirname(__file__), '..', pathname)
    )


class LibbpfErrno(IntEnum):
    LIBELF = 4000  # Libelf error
    FORMAT = auto()  # BPF object format invalid
    KVERSION = auto()  # Incorrect or no 'version' section
    ENDIAN = auto()  # Endian mismatch
    INTERNAL = auto()  # Internal error in libbpf
    RELOC = auto()  # Relocation failed
    LOAD = auto()  # Load program failure for unknown reason
    VERIFY = auto()  # Kernel verifier blocks program loading
    PROG2BIG = auto()  # Program too big
    KVER = auto()  # Incorrect kernel version
    PROGTYPE = auto()  # Kernel doesn't support this program type
    WRNGPID = auto()  # Wrong pid in netlink message
    INVSEQ = auto()  # Invalid netlink sequence
    NLPARSE = auto()  # Netlink parsing error


libbpf_errstr = {
    LibbpfErrno.LIBELF: 'Libelf error',
    LibbpfErrno.FORMAT: 'Invalid BPF object format',
    LibbpfErrno.KVERSION: 'Incorrect or missing version section',
    LibbpfErrno.ENDIAN: 'Endianness mismatch',
    LibbpfErrno.INTERNAL: 'Internal libbpf error',
    LibbpfErrno.RELOC: 'Relocation failed',
    LibbpfErrno.LOAD: 'Unknown load failure',
    LibbpfErrno.VERIFY: 'Blocked by verifier',
    LibbpfErrno.PROG2BIG: 'BPF program too large',
    LibbpfErrno.KVER: 'Incorrect kernel version',
    LibbpfErrno.PROGTYPE: 'Kernel does not support this program type',
    LibbpfErrno.WRNGPID: 'Wrong PID in netlink message',
    LibbpfErrno.INVSEQ: 'Invalid netlink sequence',
    LibbpfErrno.NLPARSE: 'Netlink parsing error',
}


def cerr(errno: int = None):
    """
    Get errno from ctypes and print it.
    """
    if errno is None:
        errno = get_errno()
    if errno < 0:
        errno = -int(errno)
    try:
        errstr = libbpf_errstr[LibbpfErrno(errno)]
    except (ValueError, KeyError):
        errstr = os.strerror(errno)
    return f'{errstr} ({errno})'


def which(program: str) -> Union[str, None]:
    """
    Find an executable in $PATH and return its abolute path
    if it exists.
    """

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    raise FileNotFoundError(f'Unable to find executable for {program}')


def assert_exists(f: str) -> None:
    """
    Raise an OSError if file @f does not exist.
    """
    if f is None or not os.path.exists(f):
        raise FileNotFoundError(f'Unable to find {f}')


def strip_end(text, suffix):
    """
    Strip the end off of a string.
    """
    if not text.endswith(suffix):
        return text
    return text[: len(text) - len(suffix)]


extension_re = re.compile(r'([^\.]*)\..*')


def strip_full_extension(pathname: str):
    """
    Strip an entire extension from a pathname.
    """
    head, tail = os.path.split(pathname)
    match = extension_re.fullmatch(tail)
    if match:
        tail = match[1]
    return os.path.join(head, tail)


def arch() -> str:
    """
    Get the current system architecture.
    """
    uname = [which('uname'), '-m']
    arch = subprocess.check_output(uname).decode('utf-8').strip()
    arch = arch.replace('x86_64', 'x86')
    return arch


def kversion() -> str:
    """
    Get the current system kernel version.
    """
    uname = [which('uname'), '-r']
    version = subprocess.check_output(uname).decode('utf-8').strip()
    return version


FILESYSTEMENCODING = sys.getfilesystemencoding()


def force_bytes(s: Union[str, bytes]):
    """
    Convert @s to bytes if it is not already bytes.
    """
    if isinstance(s, str):
        s = s.encode(FILESYSTEMENCODING)
    if not isinstance(s, bytes):
        raise Exception(f'{s} could not be converted to bytes.')
    return s


def drop_privileges(function):
    """
    Decorator to drop root privileges.
    """

    def inner(*args, **kwargs):
        # If not root, just call the function
        if os.geteuid() != 0:
            return function(*args, **kwargs)
        # Get sudoer's UID
        try:
            sudo_uid = int(os.environ['SUDO_UID'])
        except (KeyError, ValueError):
            # print("Could not get UID for sudoer", file=sys.stderr)
            # TODO log
            return
        # Get sudoer's GID
        try:
            sudo_gid = int(os.environ['SUDO_GID'])
        except (KeyError, ValueError):
            # print("Could not get GID for sudoer", file=sys.stderr)
            # TODO log
            return
        # Make sure groups are reset
        try:
            os.setgroups([])
        except PermissionError:
            # TODO log
            pass
        # Drop root
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)
        # Execute function
        ret = function(*args, **kwargs)
        # Get root back
        os.setresgid(0, 0, -1)
        os.setresuid(0, 0, -1)
        return ret

    return inner


def find_file_up_tree(fname: str, starting_dir: str = '.') -> Optional[str]:
    """
    Visit parent directories until we find file @fname.
    """
    starting_dir = os.path.abspath(starting_dir)

    if not os.path.exists(starting_dir):
        raise FileNotFoundError(
            f'Starting directory {starting_dir} does not exist'
        ) from None
    if not os.path.isdir(starting_dir):
        raise NotADirectoryError(f'Path {starting_dir} is not a directory')

    head = starting_dir

    while 1:
        if fname in os.listdir(head):
            return os.path.abspath(os.path.join(head, fname))
        if not head or head == '/':
            break
        head, _tail = os.path.split(head)

    return None

def _capitalize(s: str) -> str:
    if not s:
        return s
    if len(s) == 1:
        return s.upper()
    return s[0].upper() + s[1:]

def to_camel(s: str, upper: bool) -> str:
    """
    Convert a string to camel case.
    """
    components = re.split(r'[-_.,]', s)
    components = list(map(lambda c: _capitalize(c.strip()), components))
    if not upper:
        components[0] = components[0].lower()
    return ''.join(components)

version_re = re.compile(r'(\d*)\.(\d*)\.(\d*)\.')
kversion_cache = None
def get_encoded_kernel_version() -> int:
    global kversion_cache
    if kversion_cache is not None:
        return kversion_cache
    version = platform.release()
    match = version_re.match(version)
    if not match:
        return 0
    major = int(match[1])
    minor = int(match[2])
    patch = int(match[3])
    # /usr/include/linux/version.h
    kversion_cache = ((major) << 16) + ((minor) << 8) + patch
    return kversion_cache
