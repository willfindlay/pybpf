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

import os
import ctypes as ct
import subprocess
from typing import get_type_hints, Callable, List, Tuple

from pybpf.utils import which, arch, kversion, strip_end

"""
struct bpf_object_skeleton {
	size_t sz; /* size of this struct, for forward/backward compatibility */

	const char *name;
	void *data;
	size_t data_sz;

	struct bpf_object **obj;

	int map_cnt;
	int map_skel_sz; /* sizeof(struct bpf_skeleton_map) */
	struct bpf_map_skeleton *maps;

	int prog_cnt;
	int prog_skel_sz; /* sizeof(struct bpf_skeleton_prog) */
	struct bpf_prog_skeleton *progs;
};
"""

class BPFMapDefStruct(ct.Structure):
    """
    Keep this in sync with libbpf.
    ```
        struct bpf_map_def {
                unsigned int type;
                unsigned int key_size;
                unsigned int value_size;
                unsigned int max_entries;
                unsigned int map_flags;
        };
    ```
    """
    _fields_ = (
            ('type', ct.c_uint),
            ('key_size', ct.c_uint),
            ('value_size', ct.c_uint),
            ('max_entries', ct.c_uint),
            ('map_flags', ct.c_uint),
            )

# TODO: decide if this is needed
#class BPFObjectStruct(ct.Structure):
#    #_fields_ = ()
#    pass
#
#class BPFMapSkeletonStruct(ct.Structure):
#    #_fields_ = ()
#    pass
#
#
#class BPFObjectSkeletonStruct(ct.Structure):
#    _fields_ = (
#            ('name', ct.c_char_p),
#            ('data', ct.c_void_p),
#            ('data_sz', ct.c_size_t),
#            ('obj', ct.POINTER(ct.POINTER(BPFObjectStruct))),
#            ('map_cnt', ct.c_int),
#            ('map_skel_sz', ct.c_int),
#            ('maps', BPFMapSkeletonStruct),
#            )

_RINGBUF_CB_TYPE = ct.CFUNCTYPE(ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_int)

def skeleton_fn(skeleton: ct.CDLL) -> Callable:
    """
    A decorator that wraps a skeleton function of the same name.
    """
    def inner(func):
        name = func.__name__
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

def create_skeleton_lib(skeleton: ct.CDLL):
    # pylint: disable=no-self-argument,no-method-argument
    class Lib:
        # ====================================================================
        # Skeleton Functions
        # ====================================================================

        @skeleton_fn(skeleton)
        def pybpf_open() -> ct.c_void_p:
            pass

        @skeleton_fn(skeleton)
        def pybpf_load(bpf: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton)
        def pybpf_attach(bpf: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton)
        def pybpf_destroy(bpf: ct.c_void_p) -> None:
            pass

        @skeleton_fn(skeleton)
        def get_bpf_object(bpf: ct.c_void_p) -> ct.c_void_p:
            pass

        @skeleton_fn(skeleton)
        def bump_memlock_rlimit() -> ct.c_int:
            pass

        # ====================================================================
        # Map Functions
        # ====================================================================

        @skeleton_fn(skeleton)
        def bpf_object__find_map_fd_by_name(obj: ct.c_void_p, name: ct.c_char_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton)
        def bpf_map__fd(_map: ct.c_void_p) -> ct.c_int:
            pass

        # ====================================================================
        # Libbpf Ringbuf
        # ====================================================================

        @skeleton_fn(skeleton)
        def ring_buffer__new(map_fd: ct.c_int, sample_cb: _RINGBUF_CB_TYPE, ctx: ct.c_void_p, opts: ct.c_void_p) -> ct.c_void_p:
            pass

        @skeleton_fn(skeleton)
        def ring_buffer__free(ringbuf: ct.c_void_p) -> None:
            pass

        @skeleton_fn(skeleton)
        def ring_buffer__add(ringbuf: ct.c_void_p, map_fd: ct.c_int, sample_cb: _RINGBUF_CB_TYPE, ctx: ct.c_void_p) -> ct.c_int:
            pass

        @skeleton_fn(skeleton)
        def ring_buffer__poll(ringbuf: ct.c_void_p, timeout_ms: ct.c_int) -> ct.c_int:
            pass

        @skeleton_fn(skeleton)
        def ring_buffer__consume(ringbuf: ct.c_void_p) -> ct.c_int:
            pass

        # ====================================================================
        # Libbpf Perfbuf
        # ====================================================================

        # TODO
    # pylint: enable=no-self-argument,no-method-argument

    return Lib
