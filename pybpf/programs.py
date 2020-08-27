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

    2020-Aug-11  William Findlay  Created this.
"""

from __future__ import annotations
import ctypes as ct
from enum import IntEnum, auto
from abc import ABC
from typing import Callable, Any, Optional, Type, TYPE_CHECKING

from pybpf.lib import _RINGBUF_CB_TYPE
from pybpf.utils import cerr, force_bytes

if TYPE_CHECKING:
    from pybpf.object import BPFObject

# Maps prog type to prog class
progtype2class = {}

def register_prog(prog_type: BPFProgType):
    """
    Decorates a class to register if with the corresponding :IntEnum:BPFProgType.
    """
    def inner(prog: Type[ProgBase]):
        progtype2class[prog_type] = prog
        return prog
    return inner

class BPFProgType(IntEnum):
    """
    Integer enum representing BPF program types.
    """
    UNSPEC                  = 0
    SOCKET_FILTER           = auto()
    KPROBE                  = auto()
    SCHED_CLS               = auto()
    SCHED_ACT               = auto()
    TRACEPOINT              = auto()
    XDP                     = auto()
    PERF_EVENT              = auto()
    CGROUP_SKB              = auto()
    CGROUP_SOCK             = auto()
    LWT_IN                  = auto()
    LWT_OUT                 = auto()
    LWT_XMIT                = auto()
    SOCK_OPS                = auto()
    SK_SKB                  = auto()
    CGROUP_DEVICE           = auto()
    SK_MSG                  = auto()
    RAW_TRACEPOINT          = auto()
    CGROUP_SOCK_ADDR        = auto()
    LWT_SEG6LOCAL           = auto()
    LIRC_MODE2              = auto()
    SK_REUSEPORT            = auto()
    FLOW_DISSECTOR          = auto()
    CGROUP_SYSCTL           = auto()
    RAW_TRACEPOINT_WRITABLE = auto()
    CGROUP_SOCKOPT          = auto()
    TRACING                 = auto()
    STRUCT_OPS              = auto()
    EXT                     = auto()
    LSM                     = auto()
    SK_LOOKUP               = auto()
    # This must be the last entry
    PROG_TYPE_UNKNOWN       = auto()

def create_prog(bpf: BPFObject, prog_name: str, prog_fd: ct.c_int, prog_type: ct.c_int) -> Optional[ProgBase]:
    """
    Create a BPF prog object from a prog description.
    """
    # Convert prog type to enum
    try:
        prog_type = BPFProgType(prog_type)
    except ValueError:
        prog_type = BPFProgType.PROG_TYPE_UNKNOWN

    # Construct prog based on prog type
    try:
        return progtype2class[prog_type](bpf, prog_name, prog_fd)
    except KeyError:
        pass

    # Fall through
    raise ValueError(f'No prog implementation for {prog_type.name}')

class ProgBase(ABC):
    """
    A base class for BPF programs.
    """
    def __init__(self, bpf: BPFObject, name: str, prog_fd: int):
        self._bpf = bpf
        self._name = name
        self._prog_fd = prog_fd

    def __eq__(self, other):
        return id(self) == id(other)

    def invoke(self, data: ct.Structure = None):
        """
        Invoke the BPF program once and capture and return its return value.
        If the program is of type BPF_PROG_TYPE_USER, you can pass it data
        using a ctypes struct @data.
        """
        if data == None:
            data_p = None
            data_size = ct.c_uint32(0)
        else:
            data_p = ct.addressof(data)
            data_size = ct.sizeof(data)

        # Make this signed so that we can express negative return values,
        # should be okay to pass to the unsigned retval pointer
        bpf_ret = ct.c_uint32()

        retval = self._bpf._lib.bpf_prog_test_run(self._prog_fd, ct.c_int(1), data_p, data_size, None, ct.c_uint32(0), ct.byref(bpf_ret), None)
        if retval < 0:
            raise Exception(f'Failed to invoke BPF program {self._name}: {cerr(retval)}')

        bpf_retval = ct.c_int16(bpf_ret.value)
        return bpf_retval.value

@register_prog(BPFProgType.SOCKET_FILTER)
class ProgSocketFilter(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.KPROBE)
class ProgKprobe(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def invoke(self, data: ct.Structure = None):
        raise NotImplementedError(f'{self.__class__.__name__} programs cannot yet be invoked with bpf_prog_test_run.')

@register_prog(BPFProgType.SCHED_CLS)
class ProgSchedCls(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.SCHED_ACT)
class ProgSchedAct(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.TRACEPOINT)
class ProgTracepoint(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def invoke(self, data: ct.Structure = None):
        raise NotImplementedError(f'{self.__class__.__name__} programs cannot yet be invoked with bpf_prog_test_run.')

@register_prog(BPFProgType.XDP)
class ProgXdp(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.PERF_EVENT)
class ProgPerfEvent(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.CGROUP_SKB)
class ProgCgroupSkb(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.CGROUP_SOCK)
class ProgCgroupSock(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.LWT_IN)
class ProgLwtIn(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.LWT_OUT)
class ProgLwtOut(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.LWT_XMIT)
class ProgLwtXmit(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.SOCK_OPS)
class ProgSockOps(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.SK_SKB)
class ProgSkSkb(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.CGROUP_DEVICE)
class ProgCgroupDevice(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.SK_MSG)
class ProgSkMsg(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.RAW_TRACEPOINT)
class ProgRawTracepoint(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.CGROUP_SOCK_ADDR)
class ProgCgroupSockAddr(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.LWT_SEG6LOCAL)
class ProgLwtSeg6local(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.LIRC_MODE2)
class ProgLircMode2(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.SK_REUSEPORT)
class ProgSkReuseport(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.FLOW_DISSECTOR)
class ProgFlowDissector(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.CGROUP_SYSCTL)
class ProgCgroupSysctl(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.RAW_TRACEPOINT_WRITABLE)
class ProgRawTracepointWritable(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.CGROUP_SOCKOPT)
class ProgCgroupSockopt(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.TRACING)
class ProgTracing(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.STRUCT_OPS)
class ProgStructOps(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.EXT)
class ProgExt(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.LSM)
class ProgLsm(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

@register_prog(BPFProgType.SK_LOOKUP)
class ProgSkLookup(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
