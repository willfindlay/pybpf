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
import ctypes as ct
import subprocess
from typing import get_type_hints, Callable, List, Tuple, Generator

from pybpf.utils import which, arch, kversion, strip_end

_LIBBPF = ct.CDLL('libbpf.so', use_errno=True)

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

def libbpf_fn(name: str) -> Callable:
    """
    A decorator that wraps a libbpf function of the same name.
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
            return getattr(_LIBBPF, name)(*args, **kwargs)
        getattr(_LIBBPF, name).argtypes = argtypes
        getattr(_LIBBPF, name).restype = restype
        return wrapper
    return inner

class Lib:
    """
    Python bindings for libbpf.
    """
    # pylint: disable=no-self-argument,no-method-argument

    # ====================================================================
    # Bookkeeping
    # ====================================================================

    @libbpf_fn('bpf_object__open')
    def bpf_object_open(path: ct.c_char_p) -> ct.c_void_p:
        pass

    @libbpf_fn('bpf_object__load')
    def bpf_object_load(obj: ct.c_void_p) -> ct.c_int:
        pass

    @libbpf_fn('bpf_object__close')
    def bpf_object_close(obj: ct.c_void_p) -> None:
        pass

    # ====================================================================
    # Map Functions
    # ====================================================================

    @libbpf_fn('bpf_object__find_map_fd_by_name')
    def find_map_fd_by_name(obj: ct.c_void_p, name: ct.c_char_p) -> ct.c_int:
        pass

    @libbpf_fn('bpf_map__fd')
    def bpf_map_fd(_map: ct.c_void_p) -> ct.c_int:
        pass

    @libbpf_fn('bpf_map__type')
    def bpf_map_type(_map: ct.c_void_p) -> ct.c_int:
        pass

    @libbpf_fn('bpf_map__key_size')
    def bpf_map_key_size(_map: ct.c_void_p) -> ct.c_uint32:
        pass

    @libbpf_fn('bpf_map__value_size')
    def bpf_map_value_size(_map: ct.c_void_p) -> ct.c_uint32:
        pass

    @libbpf_fn('bpf_map__name')
    def bpf_map_name(_map: ct.c_void_p) -> ct.c_char_p:
        pass

    @libbpf_fn('bpf_map__max_entries')
    def bpf_map_max_entries(_map: ct.c_void_p) -> ct.c_uint32:
        pass

    @libbpf_fn('bpf_map__next')
    def bpf_map_next(_map: ct.c_void_p, obj: ct.c_void_p) -> ct.c_void_p:
        pass

    @libbpf_fn('bpf_map__prev')
    def bpf_map_prev(_map: ct.c_void_p, obj: ct.c_void_p) -> ct.c_void_p:
        pass

    @classmethod
    def obj_maps(cls, obj: ct.c_void_p) -> Generator[ct.c_void_p, None, None]:
        if not obj:
            raise StopIteration('Null BPF object.')
        _map = cls.bpf_map_next(None, obj)
        while _map:
            yield _map
            _map = cls.bpf_map_next(_map, obj)

    @libbpf_fn('bpf_map_lookup_elem')
    def bpf_map_lookup_elem(map_fd: ct.c_int, key: ct.c_void_p, value: ct.c_void_p) -> ct.c_int:
        pass

    @libbpf_fn('bpf_map_update_elem')
    def bpf_map_update_elem(map_fd: ct.c_int, key: ct.c_void_p, value: ct.c_void_p, flags :ct.c_int) -> ct.c_int:
        pass

    @libbpf_fn('bpf_map_delete_elem')
    def bpf_map_delete_elem(map_fd: ct.c_int, key: ct.c_void_p) -> ct.c_int:
        pass

    @libbpf_fn('bpf_map_lookup_and_delete_elem')
    def bpf_map_lookup_and_delete_elem(map_fd: ct.c_int, key: ct.c_void_p, value: ct.c_void_p) -> ct.c_int:
        pass

    @libbpf_fn('bpf_map_get_next_key')
    def bpf_map_get_next_key(map_fd: ct.c_int, key: ct.c_void_p, next_key: ct.c_void_p) -> ct.c_int:
        pass

    # ====================================================================
    # Libbpf Ringbuf
    # ====================================================================

    @libbpf_fn('ring_buffer__new')
    def ring_buffer_new(map_fd: ct.c_int, sample_cb: _RINGBUF_CB_TYPE, ctx: ct.c_void_p, opts: ct.c_void_p) -> ct.c_void_p:
        pass

    @libbpf_fn('ring_buffer__free')
    def ring_buffer_free(ringbuf: ct.c_void_p) -> None:
        pass

    @libbpf_fn('ring_buffer__add')
    def ring_buffer_add(ringbuf: ct.c_void_p, map_fd: ct.c_int, sample_cb: _RINGBUF_CB_TYPE, ctx: ct.c_void_p) -> ct.c_int:
        pass

    @libbpf_fn('ring_buffer__poll')
    def ring_buffer_poll(ringbuf: ct.c_void_p, timeout_ms: ct.c_int) -> ct.c_int:
        pass

    @libbpf_fn('ring_buffer__consume')
    def ring_buffer_consume(ringbuf: ct.c_void_p) -> ct.c_int:
        pass

    # ====================================================================
    # Program Functions
    # ====================================================================

    @libbpf_fn('bpf_program__fd')
    def bpf_program_fd(prog: ct.c_void_p) -> ct.c_int:
        pass

    @libbpf_fn('bpf_program__get_type')
    def bpf_program_type(prog: ct.c_void_p) -> ct.c_int:
        pass

    @libbpf_fn('bpf_program__name')
    def bpf_program_name(prog: ct.c_void_p) -> ct.c_char_p:
        pass

    @libbpf_fn('bpf_program__load')
    def bpf_program_load(prog: ct.c_void_p, license: ct.c_char_p, kernel_version: ct.c_uint32) -> ct.c_int:
        pass

    @libbpf_fn('bpf_program__attach')
    def bpf_program_attach(prog: ct.c_void_p) -> ct.c_void_p:
        pass

    @libbpf_fn('bpf_program__next')
    def bpf_program_next(prog: ct.c_void_p, obj: ct.c_void_p) -> ct.c_void_p:
        pass

    @libbpf_fn('bpf_program__prev')
    def bpf_program_prev(prog: ct.c_void_p, obj: ct.c_void_p) -> ct.c_void_p:
        pass

    @classmethod
    def obj_programs(cls, obj: ct.c_void_p) -> Generator[ct.c_void_p, None, None]:
        if not obj:
            raise StopIteration('Null BPF object.')
        prog = cls.bpf_program_next(None, obj)
        while prog:
            yield prog
            prog = cls.bpf_program_next(prog, obj)

    @libbpf_fn('bpf_prog_test_run')
    def bpf_prog_test_run(prog_fd: ct.c_int, repeat: ct.c_int, data: ct.c_void_p, data_size: ct.c_uint32, data_out: ct.c_void_p, data_out_size: ct.POINTER(ct.c_uint32), retval: ct.POINTER(ct.c_uint32), duration: ct.POINTER(ct.c_uint32)) -> ct.c_int:
        pass

    @libbpf_fn('bpf_program__attach_xdp')
    def bpf_program_attach_xdp(prog: ct.c_void_p, ifindex: ct.c_int) -> ct.c_void_p:
        pass

    @libbpf_fn('bpf_set_link_xdp_fd')
    def bpf_set_link_xdp_fd(ifindex: ct.c_int, progfd: ct.c_int, flags: ct.c_uint32) -> ct.c_int:
        pass

    # ====================================================================
    # Uprobe Attachment
    # ====================================================================

    @libbpf_fn('bpf_program__attach_uprobe')
    def attach_uprobe(prog: ct.c_void_p, retprobe: ct.c_bool, pid: ct.c_int, binary_path: ct.c_char_p, func_offset: ct.c_size_t) -> ct.c_void_p:
        pass

    # ====================================================================
    # Book Keeping
    # ====================================================================

    @libbpf_fn('libbpf_num_possible_cpus')
    def num_possible_cpus() -> ct.c_int:
        pass

# pylint: enable=no-self-argument,no-method-argument
