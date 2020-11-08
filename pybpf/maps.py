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

    2020-Aug-08  William Findlay  Created this.
"""

from __future__ import annotations
import ctypes as ct
from struct import pack, unpack
from collections.abc import MutableMapping
from abc import ABC
from enum import IntEnum, auto
from typing import Callable, Any, Optional, Type, Union, TYPE_CHECKING

from pybpf.lib import Lib, _RINGBUF_CB_TYPE
from pybpf.utils import cerr, force_bytes

# Maps map type to map class
maptype2class = {}


def register_map(map_type: BPFMapType):
    """
    Decorates a class to register if with the corresponding :IntEnum:BPFMapType.
    """

    def inner(_map: Type[MapBase]):
        maptype2class[map_type] = _map
        return _map

    return inner


class BPFMapType(IntEnum):
    """
    Integer enum representing BPF map types.
    """

    UNSPEC = 0
    HASH = auto()
    ARRAY = auto()
    PROG_ARRAY = auto()  # TODO
    PERF_EVENT_ARRAY = auto()  # TODO
    PERCPU_HASH = auto()
    PERCPU_ARRAY = auto()
    STACK_TRACE = auto()  # TODO
    CGROUP_ARRAY = auto()
    LRU_HASH = auto()
    LRU_PERCPU_HASH = auto()
    LPM_TRIE = auto()  # TODO
    ARRAY_OF_MAPS = auto()  # TODO
    HASH_OF_MAPS = auto()  # TODO
    DEVMAP = auto()  # TODO
    SOCKMAP = auto()  # TODO
    CPUMAP = auto()  # TODO
    XSKMAP = auto()  # TODO
    SOCKHASH = auto()  # TODO
    CGROUP_STORAGE = auto()
    REUSEPORT_SOCKARRAY = auto()  # TODO
    PERCPU_CGROUP_STORAGE = auto()  # TODO
    QUEUE = auto()
    STACK = auto()
    SK_STORAGE = auto()  # TODO
    DEVMAP_HASH = auto()  # TODO
    STRUCT_OPS = auto()  # TODO
    RINGBUF = auto()
    INODE_STORAGE = auto()
    # This must be the last entry
    MAP_TYPE_UNKNOWN = auto()


def create_map(
    skel,
    _map: ct.c_voidp,
    map_fd: ct.c_int,
    mtype: ct.c_int,
    ksize: ct.c_int,
    vsize: ct.c_int,
    max_entries: ct.c_int,
) -> Union[Type[MapBase], Type[QueueStack], Ringbuf]:
    """
    Create a BPF map object from a map description.
    """
    # Convert map type to enum
    try:
        map_type = BPFMapType(mtype)
    except ValueError:
        map_type = BPFMapType.MAP_TYPE_UNKNOWN

    if map_type == BPFMapType.RINGBUF:
        return Ringbuf(skel, _map, map_fd)

    # Construct map based on map type
    try:
        return maptype2class[map_type](_map, map_fd, ksize, vsize, max_entries)
    except KeyError:
        pass

    # Fall through
    raise ValueError(f'No map implementation for {map_type.name}')


class MapBase(MutableMapping):
    """
    A base class for BPF maps.
    """

    def __init__(
        self, _map: ct.c_void_p, map_fd: int, ksize: int, vsize: int, max_entries: int
    ):
        self._map = _map
        self._map_fd = map_fd
        self._ksize = ksize
        self._vsize = vsize
        self._max_entries = max_entries

        self.KeyType = self._no_key_type
        self.ValueType = self._no_value_type

    def _no_key_type(self, *args, **kwargs):
        raise Exception(
            f'Please define a ctype for key using {self.__class__.__name__}.register_key_type(ctype)'
        )

    def _no_value_type(self, *args, **kwargs):
        raise Exception(
            f'Please define a ctype for value using {self.__class__.__name__}.register_value_type(ctype)'
        )

    def fd(self) -> int:
        return self._map_fd

    def register_key_type(self, _type: ct.Structure):
        """
        Register a new ctype as a key type.
        """
        if ct.sizeof(_type) != self._ksize:
            raise Exception(
                f'Mismatch between key size ({self._ksize}) and size of key type ({ct.sizeof(_type)})'
            )
        self.KeyType = _type

    def register_value_type(self, _type: ct.Structure):
        """
        Register a new ctype as a value type.
        """
        if ct.sizeof(_type) != self._vsize:
            raise Exception(
                f'Mismatch between value size ({self._vsize}) and size of value type ({ct.sizeof(_type)})'
            )
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
            ret = Lib.bpf_map_get_next_key(self._map_fd, None, ct.byref(next_key))
        else:
            ret = Lib.bpf_map_get_next_key(
                self._map_fd, ct.byref(key), ct.byref(next_key)
            )

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
        ret = Lib.bpf_map_update_elem(
            self._map_fd, ct.byref(key), ct.byref(value), flags
        )
        if ret < 0:
            raise KeyError(f'Unable to update item: {cerr(ret)}')

    def __getitem__(self, key):
        value = self.ValueType()
        try:
            key = self.KeyType(key)
        except TypeError:
            pass
        ret = Lib.bpf_map_lookup_elem(self._map_fd, ct.byref(key), ct.byref(value))
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
        ret = Lib.bpf_map_delete_elem(self._map_fd, ct.byref(key))
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
    _vsize = None  # type: int

    def __init__(self, *args, **kwargs):
        self._num_cpus = Lib.num_possible_cpus()
        try:
            alignment = self._vsize % 8
        except AttributeError:
            raise Exception('PerCpuMixin without value size?!')
        # Force aligned value size
        if alignment != 0:
            self._vsize += 8 - alignment
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
            raise Exception(
                f'Mismatch between value size ({self._vsize}) and size of value type ({ct.sizeof(_type)})'
            )
        self.ValueType = _type * self._num_cpus


class LocalStorageBase(MapBase, ABC):
    """
    A base class for local storage maps. They always have a fixed key type,
    which must be specified in the child class constructor. Elements are
    garbage collected by the kernel.
    """

    def __init__(self, *args, **kwargs):
        MapBase.__init__(self, *args, **kwargs)

    def register_key_type(self, _type: ct.Structure):
        raise NotImplementedError(
            'Local storage maps always have a specific key type. This cannot be changed'
        )


@register_map(BPFMapType.HASH)
class Hash(MapBase):
    """
    A BPF hashmap.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


@register_map(BPFMapType.LRU_HASH)
class LruHash(Hash):
    """
    A BPF hashmap that discards least recently used entries when it is full.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


@register_map(BPFMapType.PERCPU_HASH)
class PerCpuHash(PerCpuMixin, Hash):
    """
    A BPF hashmap that maintains unsynchonized copies per cpu.
    """

    def __init__(self, *args, **kwargs):
        Hash.__init__(self, *args, **kwargs)
        PerCpuMixin.__init__(self, *args, **kwargs)


@register_map(BPFMapType.LRU_PERCPU_HASH)
class LruPerCpuHash(PerCpuMixin, LruHash):
    """
    A BPF hashmap that maintains unsynchonized copies per cpu and discards least
    recently used entries when it is full.
    """

    def __init__(self, *args, **kwargs):
        LruHash.__init__(self, *args, **kwargs)
        PerCpuMixin.__init__(self, *args, **kwargs)


@register_map(BPFMapType.ARRAY)
class Array(MapBase):
    """
    A BPF array. Keys are always ct.c_uint.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.KeyType = ct.c_uint

    def register_key_type(self, _type: ct.Structure):
        raise NotImplementedError(
            'Arrays always have key type ct.c_uint. This cannot be changed'
        )

    def __delitem__(self, key):
        self.__setitem__(key, self.ValueType())


@register_map(BPFMapType.CGROUP_ARRAY)
class CgroupArray(Array):
    """
    A BPF array that contains cgroup file descriptors. Userspace is expected to
    populate this map by getting a cgroup-backed fd by calling open(2) on
    a cgroup directory. Then, update the map to contain the cgroup fd.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.KeyType = ct.c_uint
        self.ValueType = ct.c_uint

    def register_value_type(self, _type: ct.Structure):
        raise NotImplementedError(
            'Cgroup always have value type ct.c_uint. This cannot be changed'
        )

    def register_key_type(self, _type: ct.Structure):
        raise NotImplementedError(
            'Cgroup always have key type ct.c_uint. This cannot be changed'
        )

    def append_cgroup(self, cgroup_path: str) -> int:
        """
        A helper to get the cgroup fd associated with the directory @cgroup_path
        and append its file descriptor to the map. Returns the array index that
        was updated on success.
        """
        with open(cgroup_path, 'r') as f:
            fd = f.fileno
        if fd < 0:
            raise Exception(f'Unable to get file descriptor for cgroup {cgroup_path}')
        key = len(self)
        self.__setitem__(key, fd)
        return key


@register_map(BPFMapType.PERCPU_ARRAY)
class PerCpuArray(PerCpuMixin, Array):
    """
    A BPF array that maintains unsynchonized copies per cpu. Keys are always
    ct.c_uint.
    """

    def __init__(self, *args, **kwargs):
        Array.__init__(self, *args, **kwargs)
        PerCpuMixin.__init__(self, *args, **kwargs)


@register_map(BPFMapType.CGROUP_STORAGE)
class CgroupStorage(LocalStorageBase):
    """
    A BPF map that maintains per-cgroup value storage. Elements of this map
    may not be created or deleted. Instead, they are automatically created
    or deleted when a BPF program is attached to a cgroup.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TODO: what is key type?


@register_map(BPFMapType.INODE_STORAGE)
class InodeStorage(LocalStorageBase):
    """
    A BPF map that maintains per-inode value storage.
    Elements are garbage collected with their inodes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.KeyType = ct.c_uint64


class QueueStack(ABC):
    """
    A base class for BPF stacks and queues.
    """

    def __init__(
        self, _map: ct.c_void_p, map_fd: int, ksize: int, vsize: int, max_entries: int
    ):
        self._map = _map
        self._map_fd = map_fd
        self._ksize = ksize
        self._vsize = vsize
        self._max_entries = max_entries

        self.ValueType = self._no_value_type

    def _no_value_type(self, *args, **kwargs):
        raise Exception(
            f'Please define a ctype for value using {self.__class__.__name__}.register_value_type(ctype)'
        )

    def fd(self) -> int:
        return self._map_fd

    def register_value_type(self, _type: ct.Structure):
        """
        Register a new ctype as a value type.
        """
        if ct.sizeof(_type) != self._vsize:
            raise Exception(
                f'Mismatch between value size ({self._vsize}) and size of value type ({ct.sizeof(_type)})'
            )
        self.ValueType = _type

    def capacity(self) -> int:
        """
        Return the capacity of the map in entries.
        """
        return self._max_entries

    def push(self, value: self.ValueType, flags: int = 0):
        """
        Push an element onto the map.
        """
        try:
            value = self.ValueType(value)
        except TypeError:
            pass
        ret = Lib.bpf_map_update_elem(self._map_fd, None, ct.byref(value), flags)
        if ret < 0:
            raise KeyError(f'Unable to push value: {cerr(ret)}')

    def pop(self) -> self.ValueType:
        """
        Pop an element from the map.
        """
        value = self.ValueType()
        ret = Lib.bpf_map_lookup_and_delete_elem(self._map_fd, None, ct.byref(value))
        if ret < 0:
            raise KeyError(f'Unable to pop value: {cerr(ret)}')
        return value

    def peek(self):
        """
        Peek an element from the map.
        """
        value = self.ValueType()
        ret = Lib.bpf_map_lookup_elem(self._map_fd, None, ct.byref(value))
        if ret < 0:
            raise KeyError(f'Unable to peek value: {cerr(ret)}')
        return value


@register_map(BPFMapType.QUEUE)
class Queue(QueueStack):
    """
    A BPF Queue map. Implements a FIFO data structure without a key type.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


@register_map(BPFMapType.STACK)
class Stack(QueueStack):
    """
    A BPF Stack map. Implements a LIFO data structure without a key type.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class Ringbuf:
    """
    A ringbuf map for passing per-event data to userspace. This class should not
    be instantiated directly. Instead, it is created automatically by the BPFObject.
    """

    def __init__(self, skel, _map: ct.c_void_p, map_fd: int):
        self._skel = skel
        self._map = _map
        self.map_fd = map_fd

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
        if not self._skel._ringbuf_mgr:
            self._skel._ringbuf_mgr = Lib.ring_buffer_new(map_fd, func, ctx, None)
            if not self._skel._ringbuf_mgr:
                raise Exception(f'Failed to create new ring buffer manager: {cerr()}')
        # Handle case where we already have a manager
        else:
            ret = Lib.ring_buffer_add(self._skel._ringbuf_mgr, map_fd, func, ctx)
            if ret != 0:
                raise Exception(
                    f'Failed to add ringbuf to ring buffer manager: {cerr(ret)}'
                )
        # Keep a refcnt so that our function doesn't get cleaned up
        self._cb = func
