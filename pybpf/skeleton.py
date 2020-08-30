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

    2020-Aug-27  William Findlay  Created this.
"""

import os
import logging
import ctypes as ct
from textwrap import dedent

from pybpf.utils import drop_privileges, strip_full_extension, to_camel, force_bytes, cerr, FILESYSTEMENCODING
from pybpf.programs import create_prog
from pybpf.maps import create_map
from pybpf.lib import Lib

logger = logging.getLogger(__name__)

def open_bpf_object(bpf_obj_path: str) -> ct.c_void_p:
    bpf_obj_path = force_bytes(bpf_obj_path)
    res = Lib.bpf_object_open(bpf_obj_path)
    if not res:
        raise Exception(f'Failed to open BPF object: {cerr()}')
    return res

def load_bpf_object(bpf_obj: ct.c_void_p):
    res = Lib.bpf_object_load(bpf_obj)
    if res < 0:
        raise Exception(f'Failed to load BPF object: {cerr()}')
    return res

def close_bpf_object(bpf_obj: ct.c_void_p):
    if not bpf_obj:
        return
    Lib.bpf_object_close(bpf_obj)

def generate_progs(bpf_obj: ct.c_void_p):
    progs = {}
    for prog in Lib.obj_programs(bpf_obj):
        if not prog:
            continue
        prog_fd = Lib.bpf_program_fd(prog)
        prog_name = Lib.bpf_program_name(prog).decode(FILESYSTEMENCODING)
        prog_type = Lib.bpf_program_type(prog)
        progs[prog_name] = create_prog(prog, prog_name, prog_type, prog_fd)
    return progs

def generate_maps(skel, bpf_obj: ct.c_void_p):
    maps = {}
    for _map in Lib.obj_maps(bpf_obj):
        if not _map:
            continue
        map_fd = Lib.bpf_map_fd(_map)
        map_name = Lib.bpf_map_name(_map).decode(FILESYSTEMENCODING)
        map_entries = Lib.bpf_map_max_entries(_map)
        map_ksize = Lib.bpf_map_key_size(_map)
        map_vsize = Lib.bpf_map_value_size(_map)
        map_type = Lib.bpf_map_type(_map)
        maps[map_name] = create_map(skel, _map, map_fd, map_type, map_ksize, map_vsize, map_entries)
    return maps

def generate_skeleton_class(bpf_obj_path: str, bpf_obj_name: str, bpf_class_name: str):
    SKEL_CLASS = f"""
    from __future__ import annotations
    from collections.abc import Mapping
    import os
    import resource
    import atexit
    from typing import Callable, Type, TypeVar, NamedTuple, Union

    from pybpf import Lib
    from pybpf.skeleton import generate_maps, generate_progs, open_bpf_object, close_bpf_object
    from pybpf.maps import MapBase, QueueStack, Ringbuf
    from pybpf.programs import ProgBase

    __all__ = ['{bpf_class_name}Skeleton']

    BPF_OBJECT = '{bpf_obj_path}'

    class ImmutableDict(Mapping):
        def __init__(self, _dict):
            self._dict = dict(_dict)
            self._hash = None

        def __getattr__(self, key):
            return self.__getitem__(key)

        def __getitem__(self, key):
            return self._dict[key]

        def __len__(self):
            return len(self._dict)

        def __iter__(self):
            return iter(self._dict)

        def __hash__(self):
            if self._hash is None:
                self._hash = hash(frozenset(self._dict.items()))
            return self._hash

        def __eq__(self, other):
            return self._dict == other._dict

        def __str__(self):
            return f'ImmutableDict({{self._dict}})'

    class ProgDict(ImmutableDict):
        def __getattr__(self, key) -> Type[ProgBase]:
            return self.__getitem__(key)

        def __getitem__(self, key) -> Type[MapBase]:
            return self._dict[key]

    class MapDict(ImmutableDict):
        def __getattr__(self, key) -> Union[Type[MapBase], Type[QueueStack], Ringbuf]:
            return self.__getitem__(key)

        def __getitem__(self, key) -> Union[Type[MapBase], Type[QueueStack], Ringbuf]:
            return self._dict[key]

    class {bpf_class_name}Skeleton:
        \"\"\"
        {bpf_class_name}Skeleton is a skeleton class that provides helper methods for accessing the BPF object {bpf_obj_name}.
        \"\"\"

        def _initialization_function(self):
            pass

        def __init__(self, autoload: bool = True, bump_rlimit: bool = True):
            self._ringbuf_mgr = None

            if os.geteuid() != 0:
                raise OSError('Using eBPF requries root privileges')

            self.progs = ProgDict({{}})
            self.maps = MapDict({{}})

            if bump_rlimit:
                self._bump_rlimit()

            if autoload:
                self._autoload()

        def _bump_rlimit(self):
            try:
                resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
            except Exception as e:
                raise OSError(f'Failed to bump memory rlimit: {{repr(e)}}') from None

        def _autoload(self):
            self.open_bpf()
            self._initialization_function()
            self.load_bpf()
            self.attach_bpf()

        def _cleanup(self):
            if self.bpf_object:
                close_bpf_object(self.bpf_object)
            if self._ringbuf_mgr:
                Lib.ring_buffer_free(self._ringbuf_mgr)

        @classmethod
        def register_init_fn(cls, fn: Callable[{bpf_class_name}Skeleton, None]) -> None:
            \"\"\"
            Register an initialization function @fn before instantiating the skeleton class. @fn should take one parameter, the skeleton object, and can then operate on the skeleton object, for example by initializing map values before the BPF programs are loaded. The initialization function is ONLY called when the skeleton is set to auto load, _after_ the BPF object has been opened but _before_ the BPF programs are loaded and attached.
            \"\"\"
            cls._initialization_function = fn

        def open_bpf(self):
            \"\"\"
            Open the BPF object managed by this skeleton.
            \"\"\"
            self.bpf_object = open_bpf_object(BPF_OBJECT)

        def load_bpf(self):
            \"\"\"
            Load the BPF programs managed by this skeleton.
            \"\"\"
            res = Lib.bpf_object_load(self.bpf_object)
            if res < 0:
                raise Exception('Unable to load BPF object')
            self.progs = ProgDict(generate_progs(self.bpf_object))
            self.maps = MapDict(generate_maps(self, self.bpf_object))
            atexit.register(self._cleanup)

        def attach_bpf(self):
            \"\"\"
            Attach the BPF programs managed by this skeleton.
            \"\"\"
            for prog in self.progs.values():
                prog.attach()

        def ringbuf_consume(self):
            \"\"\"
            Consume all open ringbuf buffers, regardless of whether or not they currently contain event data. As this method avoids making calls to epoll_wait, it is best for use cases where low latency is desired, but it can impact performance. If you are unsure, use ring_buffer_poll instead.
            \"\"\"
            if not self._ringbuf_mgr:
                raise Exception('No ring buffers to consume. '
                        'Register ring buffers using @skel.maps.ringbuf.callback()')
            return Lib.ring_buffer_consume(self._ringbuf_mgr)

        def ringbuf_poll(self, timeout: int = -1):
            \"\"\"
            Poll for events from all open ring buffers, calling the provided callback for each ringbuffer. @timeout specifies a polling timeout in ms.  By default, polling continues indefinitely.
            \"\"\"
            if not self._ringbuf_mgr:
                raise Exception('No ring buffers to poll. '
                        'Register ring buffers using @skel.maps.ringbuf.callback()')
            return Lib.ring_buffer_poll(self._ringbuf_mgr, timeout)
    """

    return SKEL_CLASS


@drop_privileges
def generate_skeleton(bpf_obj_path: str, outdir: str) -> str:
    SKEL_PREAMBLE = """
    \"\"\"
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

        WARNING: THIS FILE IS AUTOGENERATED BY PYBPF.
                 DO NOT MAKE MODIFICATIONS TO IT.

        To regenerate this file, run: "pybpf generate skeleton /path/to/prog.bpf.o"
    \"\"\"
    """

    SKEL_FILENAME = '{}_skel.py'

    bpf_obj_name = strip_full_extension(os.path.basename(bpf_obj_path))
    bpf_class_name = to_camel(bpf_obj_name, True)


    txt = SKEL_PREAMBLE
    txt += generate_skeleton_class(bpf_obj_path, bpf_obj_name, bpf_class_name)

    # Determine output path
    outfile = SKEL_FILENAME.format(bpf_obj_name)
    outpath = os.path.abspath(os.path.join(outdir, outfile))

    with open(outpath, 'w+') as f:
       f.write(dedent(txt.strip('\n')))
    logger.debug('\n' + dedent(txt.strip('\n')))

    return outpath, f'{bpf_class_name}Skeleton'
