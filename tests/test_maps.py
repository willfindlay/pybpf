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

import os
import time
import subprocess
import ctypes as ct
from multiprocessing import cpu_count

import pytest

from pybpf.object import BPFObjectBuilder
from pybpf.maps import create_map
from pybpf.utils import project_path, which

BPF_SRC = project_path('tests/bpf_src')

def test_ringbuf(builder: BPFObjectBuilder):
    """
    Test that ringbuf maps can pass data to userspace from BPF programs.
    """
    try:
        which('sleep')
    except FileNotFoundError:
        pytest.skip('sleep not found on system')

    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'ringbuf.bpf.c')).build()

    res = 0
    res2 = 0

    @obj.ringbuf_callback('ringbuf', ct.c_int)
    def _callback(ctx, data, size):
        nonlocal res
        res = data.value

    @obj.ringbuf_callback('ringbuf2', ct.c_int)
    def _callback(ctx, data, size):
        nonlocal res2
        res2 = data.value

    subprocess.check_call('sleep 0.1'.split())
    obj.ringbuf_consume()

    assert res == 5
    assert res2 == 10

    res = 0
    res2 = 0

    subprocess.check_call('sleep 0.1'.split())
    obj.ringbuf_poll(10)

    assert res == 5
    assert res2 == 10

def test_bad_ringbuf(builder: BPFObjectBuilder):
    """
    Test that attempting to register a callback for a non-existent ringbuf
    raises a KeyError.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'ringbuf.bpf.c')).build()

    with pytest.raises(KeyError):
        @obj.ringbuf_callback('ringbuf3', ct.c_int)
        def _callback(ctx, data, size):
            print('unreachable!')

def test_maps_smoke(builder: BPFObjectBuilder):
    """
    Make sure maps load properly.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    EXPECTED_MAP_COUNT = 7

    if len(obj.maps) > EXPECTED_MAP_COUNT:
        pytest.xfail(f'EXPECTED_MAP_COUNT should be updated to {len(obj.maps)}')

    assert len(obj.maps) == EXPECTED_MAP_COUNT

def test_bad_map(builder: BPFObjectBuilder):
    """
    Test that accessing a non-existent map raises a KeyError.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    with pytest.raises(KeyError):
        obj['foo']

def test_hash(builder: BPFObjectBuilder):
    """
    Test BPF_HASH.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    # Register key and value type
    obj['hash'].register_key_type(ct.c_int)
    obj['hash'].register_value_type(ct.c_int)

    assert len(obj['hash']) == 0

    # Try to query the empty map
    for i in range(obj['hash'].capacity()):
        with pytest.raises(KeyError):
            obj['hash'][i]

    # Fill the map
    for i in range(obj['hash'].capacity()):
        obj['hash'][i] = i
    assert len(obj['hash']) == obj['hash'].capacity()

    # Try to add to full map
    with pytest.raises(KeyError):
        obj['hash'][obj['hash'].capacity()] = 666

    # Query the full map
    for i in range(obj['hash'].capacity()):
        assert obj['hash'][i].value == i

    # Update an existing value
    obj['hash'][4] = 666
    assert obj['hash'][4].value == 666

    # Clear the map
    for i in range(obj['hash'].capacity()):
        del obj['hash'][i]
    assert len(obj['hash']) == 0

    # Try to query the empty map
    for i in range(obj['hash'].capacity()):
        with pytest.raises(KeyError):
            obj['hash'][i]

def test_percpu_hash(builder: BPFObjectBuilder):
    """
    Test BPF_PERCPU_HASH.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    percpu_hash = obj['percpu_hash']

    percpu_hash.register_key_type(ct.c_int)
    percpu_hash.register_value_type(ct.c_int)

    assert len(percpu_hash) == 0

    init = percpu_hash.ValueType()
    for i in range(cpu_count()):
        init[i] = i

    for i in range(percpu_hash.capacity()):
        percpu_hash[i] = init

    assert len(percpu_hash) == percpu_hash.capacity()

    for i in range(percpu_hash.capacity()):
        for j in range(cpu_count()):
            assert percpu_hash[i][j] == j

    percpu_hash.clear()

    assert len(percpu_hash) == 0

def test_lru_hash(builder: BPFObjectBuilder):
    """
    Test BPF_LRU_HASH.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    # Register key and value type
    obj['lru_hash'].register_key_type(ct.c_int)
    obj['lru_hash'].register_value_type(ct.c_int)

    assert len(obj['lru_hash']) == 0

    # Try to query the empty map
    for i in range(obj['lru_hash'].capacity()):
        with pytest.raises(KeyError):
            obj['lru_hash'][i]

    # Overfill the map
    for i in range(obj['lru_hash'].capacity() + 30):
        obj['lru_hash'][i] = i

    assert len(obj['lru_hash']) <= obj['lru_hash'].capacity()

    for i, v in obj['lru_hash'].items():
        assert i.value == v.value

    obj['lru_hash'].clear()

    assert len(obj['lru_hash']) == 0

def test_lru_percpu_hash(builder: BPFObjectBuilder):
    """
    Test BPF_LRU_PERCPU_HASH.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    lru_percpu_hash = obj['lru_percpu_hash']

    lru_percpu_hash.register_key_type(ct.c_int)
    lru_percpu_hash.register_value_type(ct.c_int)

    assert len(lru_percpu_hash) == 0

    init = lru_percpu_hash.ValueType()
    for i in range(cpu_count()):
        init[i] = i

    # Overfill the map
    for i in range(lru_percpu_hash.capacity() + 30):
        lru_percpu_hash[i] = init

    assert len(lru_percpu_hash) <= lru_percpu_hash.capacity()

    for k, v in lru_percpu_hash.items():
        for j in range(cpu_count()):
            assert v[j] == j

    lru_percpu_hash.clear()

    assert len(lru_percpu_hash) == 0

def test_array(builder: BPFObjectBuilder):
    """
    Test BPF_ARRAY.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    # Register value type
    obj['array'].register_value_type(ct.c_int)

    # It should be impossible to change the key type
    with pytest.raises(NotImplementedError):
        obj['array'].register_key_type(ct.c_int)

    assert len(obj['array']) == obj['array'].capacity()

    # Try to query the empty map
    for i in range(obj['array'].capacity()):
        obj['array'][i] == 0

    # Fill the map
    for i in range(obj['array'].capacity()):
        obj['array'][i] = i
    assert len(obj['array']) == obj['array'].capacity()

    # Try to add to full map
    with pytest.raises(KeyError):
        obj['array'][obj['array'].capacity()] = 666

    # Query the full map
    for i in range(obj['array'].capacity()):
        assert obj['array'][i].value == i

    # Update an existing value
    obj['array'][4] = 666
    assert obj['array'][4].value == 666

    # Clear the map
    for i in range(obj['array'].capacity()):
        del obj['array'][i]
    assert len(obj['array']) == obj['array'].capacity()

    # Try to query the empty map
    for i in range(obj['array'].capacity()):
        obj['array'][i] == 0

def test__percpu_array(builder: BPFObjectBuilder):
    """
    Test BPF_PERCPU_ARRAY.
    """
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    percpu_array = obj['percpu_array']

    percpu_array.register_value_type(ct.c_int)
    # It should be impossible to change the key type
    with pytest.raises(NotImplementedError):
        obj['array'].register_key_type(ct.c_int)

    assert len(percpu_array) == percpu_array.capacity()
    for i in range(percpu_array.capacity()):
        for v in percpu_array[i]:
            assert v == 0

    init = percpu_array.ValueType()
    for i in range(cpu_count()):
        init[i] = i

    for i in range(percpu_array.capacity()):
        percpu_array[i] = init

    assert len(percpu_array) == percpu_array.capacity()

    for i in range(percpu_array.capacity()):
        for j in range(cpu_count()):
            assert percpu_array[i][j] == j

    percpu_array.clear()

    assert len(percpu_array) == percpu_array.capacity()
    for i in range(percpu_array.capacity()):
        for v in percpu_array[i]:
            assert v == 0
