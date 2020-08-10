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

    2020-Aug-08  William Findlay  Created this.
"""

from __future__ import annotations
import ctypes as ct
from struct import pack, unpack
from collections.abc import MutableMapping
from abc import ABC
from enum import IntEnum, auto
from typing import Callable, Any, Optional, TYPE_CHECKING

from pybpf.lib import _RINGBUF_CB_TYPE
from pybpf.utils import cerr, force_bytes

if TYPE_CHECKING:
    from pybpf.object import BPFObject

class BPFMapType(IntEnum):
    HASH                  = auto()
    ARRAY                 = auto()
    PROG_ARRAY            = auto() # TODO
    PERF_EVENT_ARRAY      = auto() # TODO
    PERCPU_HASH           = auto()
    PERCPU_ARRAY          = auto() # TODO
    STACK_TRACE           = auto() # TODO
    CGROUP_ARRAY          = auto() # TODO
    LRU_HASH              = auto()
    LRU_PERCPU_HASH       = auto() # TODO
    LPM_TRIE              = auto() # TODO
    ARRAY_OF_MAPS         = auto() # TODO
    HASH_OF_MAPS          = auto() # TODO
    DEVMAP                = auto() # TODO
    SOCKMAP               = auto() # TODO
    CPUMAP                = auto() # TODO
    XSKMAP                = auto() # TODO
    SOCKHASH              = auto() # TODO
    CGROUP_STORAGE        = auto() # TODO
    REUSEPORT_SOCKARRAY   = auto() # TODO
    PERCPU_CGROUP_STORAGE = auto() # TODO
    QUEUE                 = auto() # TODO
    STACK                 = auto() # TODO
    SK_STORAGE            = auto() # TODO
    DEVMAP_HASH           = auto() # TODO
    STRUCT_OPS            = auto() # TODO
    RINGBUF               = auto()
    # This must be the last entry
    MAP_TYPE_UNKNOWN      = auto()

def create_map(bpf: BPFObject, map_fd: ct.c_int, mtype: ct.c_int, ksize: ct.c_int, vsize: ct.c_int, max_entries: ct.c_int) -> Optional[MapBase]:
    """
    Create a BPF map object from a map description.
    """
    # Convert map type to enum
    try:
        mtype = BPFMapType(mtype)
    except ValueError:
        mtype = BPFMapType.MAP_TYPE_UNKNOWN

    # Construct map based on map type
    if mtype == BPFMapType.HASH:
        return Hash(bpf, map_fd, ksize, vsize, max_entries)

    if mtype == BPFMapType.LRU_HASH:
        return LruHash(bpf, map_fd, ksize, vsize, max_entries)

    if mtype == BPFMapType.LRU_PERCPU_HASH:
        return LruPerCpuHash(bpf, map_fd, ksize, vsize, max_entries)

    if mtype == BPFMapType.PERCPU_HASH:
        return PerCpuHash(bpf, map_fd, ksize, vsize, max_entries)

    if mtype == BPFMapType.ARRAY:
        return Array(bpf, map_fd, ksize, vsize, max_entries)

    if mtype == BPFMapType.PERCPU_ARRAY:
        return PerCpuArray(bpf, map_fd, ksize, vsize, max_entries)

    if mtype == BPFMapType.RINGBUF:
        return Ringbuf(bpf, map_fd)

    # Fall through
    raise ValueError(f'No map implementation for {mtype.name}')

class MapBase(MutableMapping):
    """
    A base class for BPF maps.
    """
    def __init__(self, bpf: BPFObject, map_fd: int, ksize: int, vsize: int, max_entries: int):
        self._bpf = bpf
        self._map_fd = map_fd
        self._ksize = ksize
        self._vsize = vsize
        self._max_entries = max_entries

        self.KeyType = self._no_key_type
        self.ValueType = self._no_value_type

    def _no_key_type(self, *args, **kwargs):
        raise Exception(f'Please define a ctype for key using {self.__class__.__name__}.register_key_type(ctype)')

    def _no_value_type(self, *args, **kwargs):
        raise Exception(f'Please define a ctype for value using {self.__class__.__name__}.register_value_type(ctype)')

    def register_key_type(self, _type: ct.Structure):
        """
        Register a new ctype as a key type.
        """
        if ct.sizeof(_type) != self._ksize:
            raise Exception(f'Mismatch between key size ({self._ksize}) and size of key type ({ct.sizeof(_type)})')
        self.KeyType = _type

    def register_value_type(self, _type: ct.Structure):
        """
        Register a new ctype as a value type.
        """
        if ct.sizeof(_type) != self._vsize:
            raise Exception(f'Mismatch between value size ({self._vsize}) and size of value type ({ct.sizeof(_type)})')
        self.ValueType = _type

    def capacity(self) -> int:
        """
        Return the capacity of the map in entries.
        """
        return self._max_entries

    def clear(self):
        """
        Clear the map, deleting all keys.
        """
        for k in self.keys():
            try:
                self.__delitem__(k)
            except KeyError:
                pass

    class Iter:
        """
        A helper inner class to iterate through map keys.
        This class is taken from https://github.com/iovisor/bcc/blob/master/src/python/bcc/table.py
        """
        def __init__(self, _map: MapBase):
            self.map = _map
            self.key = None

        def __iter__(self):
            return self

        def __next__(self):
            return self.next()

        def next(self):
            self.key = self.map.next(self.key)
            return self.key

    def next(self, key):
        """
        Returns the next map key.
        """
        next_key = self.KeyType()

        if key is None:
            ret = self._bpf._lib.bpf_map_get_next_key(self._map_fd, None, ct.byref(next_key))
        else:
            ret = self._bpf._lib.bpf_map_get_next_key(self._map_fd, ct.byref(key), ct.byref(next_key))

        if ret < 0:
            raise StopIteration()

        return next_key

    def iter(self):
        """
        Returns an iterator through map keys.
        """
        return self.__iter__()

    def keys(self):
        """
        Returns an iterator through map keys.
        """
        return self.__iter__()

    def itervalues(self):
        """
        Yields map values.
        """
        for key in self:
            try:
                yield self[key]
            except KeyError:
                pass

    def iteritems(self):
        """
        Yields map (key, value) pairs.
        """
        for key in self:
            try:
                yield (key, self[key])
            except KeyError:
                pass

    def items(self):
        """
        Returns a list of map (key, value) pairs.
        """
        return [item for item in self.iteritems()]

    def values(self):
        """
        Returns a list of map values.
        """
        return [value for value in self.itervalues()]

    def update(self, key: self.KeyType, value: self.ValueType, flags: int):
        """
        Update a map value, operating according to specified flags.
        This provides more control than the traditional map[key] = value method.
        """
        try:
            key = self.KeyType(key)
        except TypeError:
            pass
        try:
            value = self.ValueType(value)
        except TypeError:
            pass
        ret = self._bpf._lib.bpf_map_update_elem(self._map_fd, ct.byref(key), ct.byref(value), flags)
        if ret < 0:
            raise KeyError(f'Unable to update item item: {cerr(ret)}')

    def __getitem__(self, key):
        value = self.ValueType()
        try:
            key = self.KeyType(key)
        except TypeError:
            pass
        ret = self._bpf._lib.bpf_map_lookup_elem(self._map_fd, ct.byref(key), ct.byref(value))
        if ret < 0:
            raise KeyError(f'Unable to fetch item: {cerr(ret)}')
        return value

    def __setitem__(self, key, value):
        self.update(key, value, 0)

    def __delitem__(self, key):
        try:
            key = self.KeyType(key)
        except TypeError:
            pass
        ret = self._bpf._lib.bpf_map_delete_elem(self._map_fd, ct.byref(key))
        if ret < 0:
            raise KeyError(f'Unable to delete item item: {cerr(ret)}')

    def __iter__(self):
        return self.Iter(self)

    def __len__(self):
        i = 0
        for _k in self:
            i += 1
        return i

    def __eq__(self, other):
        return id(self) == id(other)

class PerCpuMixin(ABC):
    _vsize = None # type: int
    def __init__(self, *args, **kwargs):
        try:
            self._num_cpus = self._bpf._lib.libbpf_num_possible_cpus()
        except AttributeError:
            raise Exception('PerCpuMixin without BPF program?!')
        try:
            alignment = self._vsize % 8
        except AttributeError:
            raise Exception('PerCpuMixin without value size?!')
        # Force aligned value size
        if alignment != 0:
            self._vsize += (8 - alignment)
            # Make sure we are now aligned
            alignment = self._vsize % 8
            assert alignment == 0


    def register_value_type(self, _type: ct.Structure):
        """
        Register a new ctype as a value type.
        Value must be aligned to 8 bytes.
        """
        if _type in [ct.c_int, ct.c_int8, ct.c_int16, ct.c_int32, ct.c_byte, ct.c_char]:
            _type = ct.c_int64
        elif _type in [ct.c_uint, ct.c_uint8, ct.c_uint16, ct.c_uint32, ct.c_ubyte]:
            _type = ct.c_uint64
        elif ct.sizeof(_type) % 8:
            raise ValueError('Value size for percpu maps must be 8-byte aligned')
        if ct.sizeof(_type) != self._vsize:
            raise Exception(f'Mismatch between value size ({self._vsize}) and size of value type ({ct.sizeof(_type)})')
        self.ValueType = _type * self._num_cpus

class Hash(MapBase):
    """
    A BPF hashmap.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class LruHash(Hash):
    """
    A BPF hashmap that discards least recently used entries when it is full.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class PerCpuHash(Hash, PerCpuMixin):
    """
    A BPF hashmap that maintains unsynchonized copies per cpu.
    """
    def __init__(self, *args, **kwargs):
        Hash.__init__(self, *args, **kwargs)
        PerCpuMixin.__init__(self, *args, **kwargs)

    def register_value_type(self, _type: ct.Structure):
        """
        Register a new ctype as a value type.
        Value must be aligned to 8 bytes.
        """
        return PerCpuMixin.register_value_type(self, _type)

class LruPerCpuHash(LruHash, PerCpuMixin):
    """
    A BPF hashmap that maintains unsynchonized copies per cpu and discards least
    recently used entries when it is full.
    """
    def __init__(self, *args, **kwargs):
        LruHash.__init__(self, *args, **kwargs)
        PerCpuMixin.__init__(self, *args, **kwargs)

    def register_value_type(self, _type: ct.Structure):
        """
        Register a new ctype as a value type.
        Value must be aligned to 8 bytes.
        """
        return PerCpuMixin.register_value_type(self, _type)

class Array(MapBase):
    """
    A BPF array. Keys are always ct.c_uint.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.KeyType = ct.c_uint

    def register_key_type(self, _type: ct.Structure):
        if _type == ct.c_uint:
            return
        raise NotImplementedError('Arrays always have key type ct.c_uint. This cannot be changed')

    def __delitem__(self, key):
        self.__setitem__(key, self.ValueType())

class PerCpuArray(Array, PerCpuMixin):
    """
    A BPF array that maintains unsynchonized copies per cpu. Keys are always
    ct.c_uint.
    """
    def __init__(self, *args, **kwargs):
        Array.__init__(self, *args, **kwargs)
        PerCpuMixin.__init__(self, *args, **kwargs)

    def register_value_type(self, _type: ct.Structure):
        """
        Register a new ctype as a value type.
        Value must be aligned to 8 bytes.
        """
        return PerCpuMixin.register_value_type(self, _type)

class Ringbuf:
    """
    A ringbuf map for passing per-event data to userspace. This class should not
    be instantiated directly. Instead, it is created automatically by the BPFObject.
    """
    def __init__(self, bpf: BPFObject, map_fd: int):
        self.bpf = bpf
        self.map_fd = map_fd

        # Look up ringbuf fd by its name
        if self.map_fd < 0:
            raise Exception(f'Bad file descriptor for ringbuf')

        self._cb = None

    def callback(self, data_type: Optional[ct.Structure] = None) -> Callable:
        """
        The ringbuf map is the canonical way to pass per-event data to
        userspace. This decorator marks a function as a callback for events
        from @ringbuf.

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
        if not self.bpf.obj:
            raise Exception(f'Unable to register ringbuf callback: No BPF object loaded')

        # Decorator to register the ringbuf callback
        def inner(func):
            def wrapper(ctx, data, size):
                # Auto convert data type if provided
                if data_type is not None:
                    data = ct.cast(data, ct.POINTER(data_type)).contents
                # Call the callback
                ret = func(ctx, data, size)
                # Callback should always return an int
                # If not, fall back to returning zero
                try:
                    ret = int(ret)
                except Exception:
                    ret = 0
                return ret
            # Open ringbug with provided callback
            self._open(self.map_fd, wrapper)
            return wrapper
        return inner

    def _open(self, map_fd: ct.c_int, func: Callable, ctx: ct.c_void_p = None) -> None:
        """
        Open a new ringbuf with @func as a callback.
        """
        # Cast func as _RINGBUF_CB_TYPE
        func = _RINGBUF_CB_TYPE(func)
        # Handle case where we don't have a manager yet
        if not self.bpf._ringbuf_mgr:
            self.bpf._ringbuf_mgr = self.bpf._lib.ring_buffer__new(map_fd, func, ctx, None)
            if not self.bpf._ringbuf_mgr:
                raise Exception(f'Failed to create new ring buffer manager: {cerr()}')
        # Handle case where we already have a manager
        else:
            ret = self.bpf._lib.ring_buffer__add(self.bpf._ringbuf_mgr, map_fd, func, ctx)
            if ret != 0:
                raise Exception(f'Failed to add ringbuf to ring buffer manager: {cerr(ret)}')
        # Keep a refcnt so that our function doesn't get cleaned up
        self._cb = func
