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

import os
import time
import subprocess
import ctypes as ct
from multiprocessing import cpu_count

import pytest

from pybpf.maps import create_map
from pybpf.utils import project_path, which

BPF_SRC = project_path('tests/bpf_src')

def test_ringbuf(skeleton):
    """
    Test that ringbuf maps can pass data to userspace from BPF programs.
    """
    try:
        which('sleep')
    except FileNotFoundError:
        pytest.skip('sleep not found on system')

    skel = skeleton(os.path.join(BPF_SRC, 'ringbuf.bpf.c'))

    res = 0
    res2 = 0

    @skel.maps.ringbuf.callback(ct.c_int)
    def _callback(ctx, data, size):
        nonlocal res
        res = data.value

    @skel.maps.ringbuf2.callback(ct.c_int)
    def _callback(ctx, data, size):
        nonlocal res2
        res2 = data.value

    subprocess.check_call('sleep 0.1'.split())
    skel.ringbuf_consume()

    assert res == 5
    assert res2 == 10

    res = 0
    res2 = 0

    subprocess.check_call('sleep 0.1'.split())
    skel.ringbuf_poll(10)

    assert res == 5
    assert res2 == 10

def test_bad_ringbuf(skeleton):
    """
    Test that attempting to register a callback for a non-existent ringbuf
    raises a KeyError.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'ringbuf.bpf.c'))

    with pytest.raises(KeyError):
        @skel.maps.ringbuf3.callback(ct.c_int)
        def _callback(ctx, data, size):
            print('unreachable!')

def test_maps_smoke(skeleton):
    """
    Make sure maps load properly.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    EXPECTED_MAP_COUNT = 9

    if len(skel.maps) > EXPECTED_MAP_COUNT:
        pytest.xfail(f'EXPECTED_MAP_COUNT should be updated to {len(skel.maps)}')

    assert len(skel.maps) == EXPECTED_MAP_COUNT

def test_bad_map(skeleton):
    """
    Test that accessing a non-existent map raises a KeyError.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    with pytest.raises(KeyError):
        skel.maps.foo

    with pytest.raises(KeyError):
        skel.maps['foo']

def test_hash(skeleton):
    """
    Test BPF_HASH.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    # Register key and value type
    skel.maps.hash.register_key_type(ct.c_int)
    skel.maps.hash.register_value_type(ct.c_int)

    _hash = skel.maps.hash

    assert len(_hash) == 0

    # Try to query the empty map
    for i in range(_hash.capacity()):
        with pytest.raises(KeyError):
            _hash[i]

    # Fill the map
    for i in range(_hash.capacity()):
        _hash[i] = i
    assert len(_hash) == _hash.capacity()

    # Try to add to full map
    with pytest.raises(KeyError):
        _hash[_hash.capacity()] = 666

    # Query the full map
    for i in range(_hash.capacity()):
        assert _hash[i].value == i

    # Update an existing value
    _hash[4] = 666
    assert _hash[4].value == 666

    # Clear the map
    for i in range(_hash.capacity()):
        del _hash[i]
    assert len(_hash) == 0

    # Try to query the empty map
    for i in range(_hash.capacity()):
        with pytest.raises(KeyError):
            _hash[i]

def test_percpu_hash(skeleton):
    """
    Test BPF_PERCPU_HASH.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    percpu_hash = skel.maps.percpu_hash

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

def test_lru_hash(skeleton):
    """
    Test BPF_LRU_HASH.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    # Register key and value type
    skel.maps.lru_hash.register_key_type(ct.c_int)
    skel.maps.lru_hash.register_value_type(ct.c_int)

    lru_hash = skel.maps.lru_hash

    assert len(lru_hash) == 0

    # Try to query the empty map
    for i in range(lru_hash.capacity()):
        with pytest.raises(KeyError):
            lru_hash[i]

    # Overfill the map
    for i in range(lru_hash.capacity() + 30):
        lru_hash[i] = i

    assert len(lru_hash) <= lru_hash.capacity()

    for i, v in lru_hash.items():
        assert i.value == v.value

    lru_hash.clear()

    assert len(lru_hash) == 0

def test_lru_percpu_hash(skeleton):
    """
    Test BPF_LRU_PERCPU_HASH.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    lru_percpu_hash = skel.maps.lru_percpu_hash

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

def test_array(skeleton):
    """
    Test BPF_ARRAY.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    array = skel.maps.array

    # Register value type
    array.register_value_type(ct.c_int)

    # It should be impossible to change the key type
    with pytest.raises(NotImplementedError):
        array.register_key_type(ct.c_int)

    assert len(array) == array.capacity()

    # Try to query the empty map
    for i in range(array.capacity()):
        array[i] == 0

    # Fill the map
    for i in range(array.capacity()):
        array[i] = i
    assert len(array) == array.capacity()

    # Try to add to full map
    with pytest.raises(KeyError):
        array[array.capacity()] = 666

    # Query the full map
    for i in range(array.capacity()):
        assert array[i].value == i

    # Update an existing value
    array[4] = 666
    assert array[4].value == 666

    # Clear the map
    for i in range(array.capacity()):
        del array[i]
    assert len(array) == array.capacity()

    # Try to query the empty map
    for i in range(array.capacity()):
        array[i] == 0

def test_percpu_array(skeleton):
    """
    Test BPF_PERCPU_ARRAY.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    percpu_array = skel.maps.percpu_array

    percpu_array.register_value_type(ct.c_int)
    # It should be impossible to change the key type
    with pytest.raises(NotImplementedError):
        percpu_array.register_key_type(ct.c_int)

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

def test_prog_array(skeleton):
    """
    Test BPF_PROG_ARRAY.
    """
    pytest.skip('TODO')

def test_perf_event_array(skeleton):
    """
    Test BPF_PERF_EVENT_ARRAY.
    """
    pytest.skip('TODO')

def test_stack_trace(skeleton):
    """
    Test BPF_STACK_TRACE.
    """
    pytest.skip('TODO')

def test_cgroup_array(skeleton):
    """
    Test BPF_CGROUP_ARRAY.
    """
    pytest.skip('TODO')

def test_lpm_trie(skeleton):
    """
    Test BPF_LPM_TRIE.
    """
    pytest.skip('TODO')

def test_array_of_maps(skeleton):
    """
    Test BPF_ARRAY_OF_MAPS.
    """
    pytest.skip('TODO')

def test_hash_of_maps(skeleton):
    """
    Test BPF_HASH_OF_MAPS.
    """
    pytest.skip('TODO')

def test_devmap(skeleton):
    """
    Test BPF_DEVMAP.
    """
    pytest.skip('TODO')

def test_sockmap(skeleton):
    """
    Test BPF_SOCKMAP.
    """
    pytest.skip('TODO')

def test_cpumap(skeleton):
    """
    Test BPF_CPUMAP.
    """
    pytest.skip('TODO')

def test_xskmap(skeleton):
    """
    Test BPF_XSKMAP.
    """
    pytest.skip('TODO')

def test_sockhash(skeleton):
    """
    Test BPF_SOCKHASH.
    """
    pytest.skip('TODO')

def test_cgroup_storage(skeleton):
    """
    Test BPF_CGROUP_STORAGE.
    """
    pytest.skip('TODO')

def test_reuseport_sockarray(skeleton):
    """
    Test BPF_REUSEPORT_SOCKARRAY.
    """
    pytest.skip('TODO')

def test_percpu_cgroup_storage(skeleton):
    """
    Test BPF_PERCPU_CGROUP_STORAGE.
    """
    pytest.skip('TODO')

def test_queue(skeleton):
    """
    Test BPF_QUEUE.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    queue = skel.maps.queue

    queue.register_value_type(ct.c_int)

    for i in range(queue.capacity()):
        queue.push(i)

    with pytest.raises(KeyError):
        queue.push(666)

    for i in range(queue.capacity()):
        assert queue.peek().value == i
        assert queue.peek().value == queue.pop().value

    with pytest.raises(KeyError):
        queue.peek()

    with pytest.raises(KeyError):
        queue.pop()

def test_stack(skeleton):
    """
    Test BPF_STACK.
    """
    skel = skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))

    stack = skel.maps.stack

    stack.register_value_type(ct.c_int)

    for i in range(stack.capacity()):
        stack.push(i)

    with pytest.raises(KeyError):
        stack.push(666)

    for i in reversed(range(stack.capacity())):
        assert stack.peek().value == i
        assert stack.peek().value == stack.pop().value

    with pytest.raises(KeyError):
        stack.peek()

    with pytest.raises(KeyError):
        stack.pop()

def test_sk_storage(skeleton):
    """
    Test BPF_SK_STORAGE.
    """
    pytest.skip('TODO')

def test_devmap_hash(skeleton):
    """
    Test BPF_DEVMAP_HASH.
    """
    pytest.skip('TODO')

def test_struct_ops(skeleton):
    """
    Test BPF_STRUCT_OPS.
    """
    pytest.skip('TODO')

