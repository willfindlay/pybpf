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

from __future__ import annotations
import os
import shutil
import ctypes as ct
import subprocess
import atexit
from typing import List, Optional, Callable, Union

from pybpf.lib import create_skeleton_lib, _RINGBUF_CB_TYPE
from pybpf.utils import kversion, arch, which, assert_exists, module_path, cerr, force_bytes, FILESYSTEMENCODING, strip_full_extension, drop_privileges
from pybpf.maps import create_map, Ringbuf, MapBase, QueueStack
from pybpf.programs import create_prog, ProgBase

SKEL_OBJ_IN = module_path('cc/libpybpf.c.in')

class BPFObject:
    """
    A BPF object. This class should not be instantiated directly.
    Instead, create it using BPFObjectBuilder.
    """
    def __init__(self, skeleton_obj_file: str, bump_rlimit: bool = True, autoload: bool = True):
        self._lib = create_skeleton_lib(ct.CDLL(skeleton_obj_file))

        self._bump_rlimit = bump_rlimit
        self._bpf_loaded = False
        self._cleaned_up = False

        self._progs = {}
        self._maps = {}
        self._ringbuf_mgr = None

        if autoload:
            # Auto load BPF program
            self._bpf_autoload()

    def ringbuf_callback(self, name, data_type: Optional[ct.Structure] = None):
        """
        The ringbuf map is the canonical way to pass per-event data to
        userspace. This decorator marks a function as a callback for events
        from @ringbuf.

        @ringbuf must be declared as a ringbuf map in the BPF program.

        @data_type may be specified to automatically convert the data pointer to
        the appropriate ctype. Otherwise, this conversion must be done manually.

        The decorated function must have the following signature:
        ```
            def _callback(ctx: Any, data: ct.c_void_p, size: int):
                # Do work
        ```

        Optionally, the function may return a non-zero integer to indicate that
        polling should be stopped.
        """
        ringbuf = self.map(name)
        if not isinstance(ringbuf, Ringbuf):
            raise Exception(f'Map {name} is not a ringbuf')
        return ringbuf.callback(data_type)

    def ringbuf_consume(self):
        """
        Consume all open ringbuf buffers, regardless of whether or not they
        currently contain event data. As this method avoids making calls to
        epoll_wait, it is best for use cases where low latency is desired, but
        it can impact performance. If you are unsure, use ring_buffer_poll
        instead.
        """
        if not self._ringbuf_mgr:
            raise Exception('No ring buffers to consume. '
                    'Register ring buffers using '
                    '@BPFObject["map"].callback(DataType).')
        return self._lib.ring_buffer__consume(self._ringbuf_mgr)

    def ringbuf_poll(self, timeout: int = -1):
        """
        Poll for events from all open ring buffers, calling the provided
        callback for each ringbuffer. @timeout specifies a polling timeout in
        ms.  By default, polling continues indefinitely.
        """
        if not self._ringbuf_mgr:
            raise Exception('No ring buffers to consume. '
                    'Register ring buffers using '
                    '@BPFObject["map"].callback(DataType).')
        return self._lib.ring_buffer__poll(self._ringbuf_mgr, timeout)

    def load_bpf(self, initialization_function: Callable[['Obj'], None] = lambda obj: None) -> None:
        """
        Load BPF programs, bumping rlimit to infinity if configured to do so,
        and calling @initialization_function(obj) before loading takes place.
        Calling this manually is only necessary if BPFObject is _not_ set to
        autload BPF programs. This may be desirable if an initialization_function
        is necessary, for example to set .rodata, .bss, or .data segments.
        """
        if self._bpf_loaded:
            raise Exception('BPF programs have already been loaded. '
                    'This error may caused by trying to manually load BPF '
                    'programs after the BPFObject has been set to autoload BPF '
                    'programs.')

        # Raise an OSError if we don't have root privileges
        self._force_root()

        # Bump rlimit to infinity so we can load out BPF program
        # The user might prefer to do this manually, so make this step optional
        if self._bump_rlimit:
            ret = self._lib.bump_memlock_rlimit()
            if ret != 0:
                raise Exception(f'Failed to bump rlimit to infinity: {cerr(ret)}')

        # Open the BPF program
        self.bpf = self._lib.pybpf_open()
        if self.bpf == 0:
            raise Exception(f'Failed to open BPF object: {cerr()}')

        # Get the raw BPF object
        self.obj = self._lib.get_bpf_object(self.bpf)
        if self.obj == 0:
            raise Exception(f'Failed to get BPF object: {cerr()}')

        # Call the provided initialization function
        initialization_function(self.obj)

        # Load the BPF object
        ret = self._lib.pybpf_load(self.bpf)
        if ret != 0:
            raise Exception(f'Failed to load BPF object: {cerr(ret)}')

        # Attach BPF programs
        ret = self._lib.pybpf_attach(self.bpf)
        if ret != 0:
            raise Exception(f'Failed to attach BPF programs: {cerr(ret)}')

        # Create maps
        for _map in self._lib.obj_maps(self.obj):
            if not _map:
                continue
            map_mtype = self._lib.bpf_map__type(_map)
            map_fd = self._lib.bpf_map__fd(_map)
            map_name = self._lib.bpf_map__name(_map).decode(FILESYSTEMENCODING)
            map_ksize = self._lib.bpf_map__key_size(_map)
            map_vsize = self._lib.bpf_map__value_size(_map)
            max_entries = self._lib.bpf_map__max_entries(_map)

            self._maps[map_name] = create_map(self, map_fd, map_mtype, map_ksize, map_vsize, max_entries)

        # Create programs
        for prog in self._lib.obj_programs(self.obj):
            if not prog:
                continue
            prog_fd = self._lib.bpf_program__fd(prog)
            prog_name = self._lib.bpf_program__name(prog).decode(FILESYSTEMENCODING)
            prog_type = self._lib.bpf_program__get_type(prog)

            self._progs[prog_name] = create_prog(self, prog_name, prog_fd, prog_type)

        # Make sure we clean up libbpf memory when the program exits
        atexit.register(self._cleanup)

        self._bpf_loaded = True

    def _cleanup(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True
        # Destroy libbpf objects
        self._lib.pybpf_destroy(self.bpf)
        # Free ring buffers
        if self._ringbuf_mgr:
            self._lib.ring_buffer__free(self._ringbuf_mgr)
        self._bpf_loaded = False

    def _bpf_autoload(self) -> None:
        self.load_bpf()

    def _force_root(self) -> None:
        if os.geteuid() != 0:
            raise OSError('You neep root privileges to load BPF programs into the kernel.')

    def map(self, name: str) -> Union[MapBase, Ringbuf, QueueStack]:
        try:
            return self._maps[name]
        except KeyError:
            raise KeyError(f'No such map "{name}"') from None

    def prog(self, name: str) -> Union[ProgBase]:
        try:
            return self._progs[name]
        except KeyError:
            raise KeyError(f'No such program "{name}"') from None
