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
from typing import Callable, Any, Optional, TYPE_CHECKING

from pybpf.lib import _RINGBUF_CB_TYPE
from pybpf.utils import cerr, force_bytes

if TYPE_CHECKING:
    from pybpf.object import BPFObject

class BPFProgType(IntEnum):
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
        return prog_type2class[prog_type](bpf, prog_name, prog_fd)
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

class ProgSocketFilter(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgKprobe(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def invoke(self, data: ct.Structure = None):
        raise NotImplementedError(f'{self.__class__.__name__} programs cannot yet be invoked with bpf_prog_test_run.')

class ProgSchedCls(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgSchedAct(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgTracepoint(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def invoke(self, data: ct.Structure = None):
        raise NotImplementedError(f'{self.__class__.__name__} programs cannot yet be invoked with bpf_prog_test_run.')

class ProgXdp(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgPerfEvent(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgCgroupSkb(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgCgroupSock(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgLwtIn(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgLwtOut(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgLwtXmit(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgSockOps(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgSkSkb(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgCgroupDevice(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgSkMsg(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgRawTracepoint(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgCgroupSockAddr(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgLwtSeg6local:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgLircMode2:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgSkReuseport(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgFlowDissector(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgCgroupSysctl(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgRawTracepointWritable(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgCgroupSockopt(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgTracing(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgStructOps(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgExt(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgLsm(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class ProgSkLookup(ProgBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

prog_type2class = {
    BPFProgType.SOCKET_FILTER: ProgSocketFilter,
    BPFProgType.KPROBE: ProgKprobe,
    BPFProgType.SCHED_CLS: ProgSchedCls,
    BPFProgType.SCHED_ACT: ProgSchedAct,
    BPFProgType.TRACEPOINT: ProgTracepoint,
    BPFProgType.XDP: ProgXdp,
    BPFProgType.PERF_EVENT: ProgPerfEvent,
    BPFProgType.CGROUP_SKB: ProgCgroupSkb,
    BPFProgType.CGROUP_SOCK: ProgCgroupSock,
    BPFProgType.LWT_IN: ProgLwtIn,
    BPFProgType.LWT_OUT: ProgLwtOut,
    BPFProgType.LWT_XMIT: ProgLwtXmit,
    BPFProgType.SOCK_OPS: ProgSockOps,
    BPFProgType.SK_SKB: ProgSkSkb,
    BPFProgType.CGROUP_DEVICE: ProgCgroupDevice,
    BPFProgType.SK_MSG: ProgSkMsg,
    BPFProgType.RAW_TRACEPOINT: ProgRawTracepoint,
    BPFProgType.CGROUP_SOCK_ADDR: ProgCgroupSockAddr,
    BPFProgType.LWT_SEG6LOCAL: ProgLwtSeg6local,
    BPFProgType.LIRC_MODE2: ProgLircMode2,
    BPFProgType.SK_REUSEPORT: ProgSkReuseport,
    BPFProgType.FLOW_DISSECTOR: ProgFlowDissector,
    BPFProgType.CGROUP_SYSCTL: ProgCgroupSysctl,
    BPFProgType.RAW_TRACEPOINT_WRITABLE: ProgRawTracepointWritable,
    BPFProgType.CGROUP_SOCKOPT: ProgCgroupSockopt,
    BPFProgType.TRACING: ProgTracing,
    BPFProgType.STRUCT_OPS: ProgStructOps,
    BPFProgType.EXT: ProgExt,
    BPFProgType.LSM: ProgLsm,
    BPFProgType.SK_LOOKUP: ProgSkLookup,
}
