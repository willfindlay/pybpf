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

    2020-Aug-02  William Findlay  Created this.
"""

from __future__ import annotations
import os
import ctypes as ct
import subprocess
from typing import get_type_hints, Callable, List, Tuple, Generator

from pybpf.utils import which, arch, kversion, strip_end

_RINGBUF_CB_TYPE = ct.CFUNCTYPE(ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_int)

def skeleton_fn(skeleton: ct.CDLL, name: str) -> Callable:
    """
    A decorator that wraps a skeleton function of the same name.
    """
    def inner(func):
        th = get_type_hints(func)
        argtypes = [v for k, v in th.items() if k != 'return']
        try:
            restype = th['return']
            if restype == type(None):
                restype = None
        except KeyError:
            restype = None
        @staticmethod
        def wrapper(*args, **kwargs):
            return getattr(skeleton, name)(*args, **kwargs)
        getattr(skeleton, name).argtypes = argtypes
        getattr(skeleton, name).restype = restype
        return wrapper
    return inner

def create_skeleton_lib(skeleton: ct.CDLL) -> 'Lib':
    """
    Create a skeleton library interface.
    Keep this in sync with libbpf and libpybpf.c.in.
    """
    # pylint: disable=no-self-argument,no-method-argument
    class Lib:
        # ====================================================================
        # Skeleton Functions
        # ====================================================================

        @skeleton_fn(skeleton, 'pybpf_open')
        def pybpf_open() -> ct.c_void_p:
            pass

        @skeleton_fn(skeleton, 'pybpf_load')
        def pybpf_load(bpf: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'pybpf_attach')
        def pybpf_attach(bpf: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'pybpf_destroy')
        def pybpf_destroy(bpf: ct.c_void_p) -> None:
            pass

        @skeleton_fn(skeleton, 'get_bpf_object')
        def get_bpf_object(bpf: ct.c_void_p) -> ct.c_void_p:
            pass

        @skeleton_fn(skeleton, 'bump_memlock_rlimit')
        def bump_memlock_rlimit() -> ct.c_int:
            pass

        # ====================================================================
        # Map Functions
        # ====================================================================

        @skeleton_fn(skeleton, 'bpf_object__find_map_fd_by_name')
        def bpf_object__find_map_fd_by_name(obj: ct.c_void_p, name: ct.c_char_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'bpf_map__fd')
        def bpf_map__fd(_map: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'bpf_map__type')
        def bpf_map__type(_map: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'bpf_map__key_size')
        def bpf_map__key_size(_map: ct.c_void_p) -> ct.c_uint32:
            pass

        @skeleton_fn(skeleton, 'bpf_map__value_size')
        def bpf_map__value_size(_map: ct.c_void_p) -> ct.c_uint32:
            pass

        @skeleton_fn(skeleton, 'bpf_map__name')
        def bpf_map__name(_map: ct.c_void_p) -> ct.c_char_p:
            pass

        @skeleton_fn(skeleton, 'bpf_map__max_entries')
        def bpf_map__max_entries(_map: ct.c_void_p) -> ct.c_uint32:
            pass

        @skeleton_fn(skeleton, 'bpf_map__next')
        def _bpf_map__next(_map: ct.c_void_p, obj: ct.c_void_p) -> ct.c_void_p:
            pass

        @skeleton_fn(skeleton, 'bpf_map__prev')
        def _bpf_map__prev(_map: ct.c_void_p, obj: ct.c_void_p) -> ct.c_void_p:
            pass

        @classmethod
        def obj_maps(cls, obj: ct.c_void_p) -> Generator[ct.c_void_p, None, None]:
            if not obj:
                raise StopIteration('Null BPF object.')
            _map = cls._bpf_map__next(None, obj)
            while _map:
                yield _map
                _map = cls._bpf_map__next(_map, obj)

        @skeleton_fn(skeleton, 'bpf_map_lookup_elem')
        def bpf_map_lookup_elem(map_fd: ct.c_int, key: ct.c_void_p, value: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'bpf_map_update_elem')
        def bpf_map_update_elem(map_fd: ct.c_int, key: ct.c_void_p, value: ct.c_void_p, flags :ct.c_int) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'bpf_map_delete_elem')
        def bpf_map_delete_elem(map_fd: ct.c_int, key: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'bpf_map_get_next_key')
        def bpf_map_get_next_key(map_fd: ct.c_int, key: ct.c_void_p, next_key: ct.c_void_p) -> ct.c_int:
            pass

        # ====================================================================
        # Libbpf Ringbuf
        # ====================================================================

        @skeleton_fn(skeleton, 'ring_buffer__new')
        def ring_buffer__new(map_fd: ct.c_int, sample_cb: _RINGBUF_CB_TYPE, ctx: ct.c_void_p, opts: ct.c_void_p) -> ct.c_void_p:
            pass

        @skeleton_fn(skeleton, 'ring_buffer__free')
        def ring_buffer__free(ringbuf: ct.c_void_p) -> None:
            pass

        @skeleton_fn(skeleton, 'ring_buffer__add')
        def ring_buffer__add(ringbuf: ct.c_void_p, map_fd: ct.c_int, sample_cb: _RINGBUF_CB_TYPE, ctx: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'ring_buffer__poll')
        def ring_buffer__poll(ringbuf: ct.c_void_p, timeout_ms: ct.c_int) -> ct.c_int:
            pass

        @skeleton_fn(skeleton, 'ring_buffer__consume')
        def ring_buffer__consume(ringbuf: ct.c_void_p) -> ct.c_int:
            pass
    # pylint: enable=no-self-argument,no-method-argument

    return Lib
