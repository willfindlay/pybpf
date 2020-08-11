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

from pybpf.project_init import ProjectInit
from pybpf.object import BPFObject
from pybpf.maps import create_map
from pybpf.utils import project_path, which

BPF_SRC = project_path('tests/bpf_src')

def test_ringbuf(init: ProjectInit):
    """
    Test that ringbuf maps can pass data to userspace from BPF programs.
    """
    try:
        which('sleep')
    except FileNotFoundError:
        pytest.skip('sleep not found on system')

    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'ringbuf.bpf.c'))
    obj = BPFObject(so, True, True)

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

def test_bad_ringbuf(init: ProjectInit):
    """
    Test that attempting to register a callback for a non-existent ringbuf
    raises a KeyError.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'ringbuf.bpf.c'))
    obj = BPFObject(so, True, True)

    with pytest.raises(KeyError):
        @obj.ringbuf_callback('ringbuf3', ct.c_int)
        def _callback(ctx, data, size):
            print('unreachable!')

def test_maps_smoke(init: ProjectInit):
    """
    Make sure maps load properly.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    EXPECTED_MAP_COUNT = 9

    if len(obj._maps) > EXPECTED_MAP_COUNT:
        pytest.xfail(f'EXPECTED_MAP_COUNT should be updated to {len(obj._maps)}')

    assert len(obj._maps) == EXPECTED_MAP_COUNT

def test_bad_map(init: ProjectInit):
    """
    Test that accessing a non-existent map raises a KeyError.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    with pytest.raises(KeyError):
        obj.map('foo')

def test_hash(init: ProjectInit):
    """
    Test BPF_HASH.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    # Register key and value type
    obj.map('hash').register_key_type(ct.c_int)
    obj.map('hash').register_value_type(ct.c_int)

    assert len(obj.map('hash')) == 0

    # Try to query the empty map
    for i in range(obj.map('hash').capacity()):
        with pytest.raises(KeyError):
            obj.map('hash')[i]

    # Fill the map
    for i in range(obj.map('hash').capacity()):
        obj.map('hash')[i] = i
    assert len(obj.map('hash')) == obj.map('hash').capacity()

    # Try to add to full map
    with pytest.raises(KeyError):
        obj.map('hash')[obj.map('hash').capacity()] = 666

    # Query the full map
    for i in range(obj.map('hash').capacity()):
        assert obj.map('hash')[i].value == i

    # Update an existing value
    obj.map('hash')[4] = 666
    assert obj.map('hash')[4].value == 666

    # Clear the map
    for i in range(obj.map('hash').capacity()):
        del obj.map('hash')[i]
    assert len(obj.map('hash')) == 0

    # Try to query the empty map
    for i in range(obj.map('hash').capacity()):
        with pytest.raises(KeyError):
            obj.map('hash')[i]

def test_percpu_hash(init: ProjectInit):
    """
    Test BPF_PERCPU_HASH.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    percpu_hash = obj.map('percpu_hash')

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

def test_lru_hash(init: ProjectInit):
    """
    Test BPF_LRU_HASH.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    # Register key and value type
    obj.map('lru_hash').register_key_type(ct.c_int)
    obj.map('lru_hash').register_value_type(ct.c_int)

    assert len(obj.map('lru_hash')) == 0

    # Try to query the empty map
    for i in range(obj.map('lru_hash').capacity()):
        with pytest.raises(KeyError):
            obj.map('lru_hash')[i]

    # Overfill the map
    for i in range(obj.map('lru_hash').capacity() + 30):
        obj.map('lru_hash')[i] = i

    assert len(obj.map('lru_hash')) <= obj.map('lru_hash').capacity()

    for i, v in obj.map('lru_hash').items():
        assert i.value == v.value

    obj.map('lru_hash').clear()

    assert len(obj.map('lru_hash')) == 0

def test_lru_percpu_hash(init: ProjectInit):
    """
    Test BPF_LRU_PERCPU_HASH.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    lru_percpu_hash = obj.map('lru_percpu_hash')

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

def test_array(init: ProjectInit):
    """
    Test BPF_ARRAY.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    # Register value type
    obj.map('array').register_value_type(ct.c_int)

    # It should be impossible to change the key type
    with pytest.raises(NotImplementedError):
        obj.map('array').register_key_type(ct.c_int)

    assert len(obj.map('array')) == obj.map('array').capacity()

    # Try to query the empty map
    for i in range(obj.map('array').capacity()):
        obj.map('array')[i] == 0

    # Fill the map
    for i in range(obj.map('array').capacity()):
        obj.map('array')[i] = i
    assert len(obj.map('array')) == obj.map('array').capacity()

    # Try to add to full map
    with pytest.raises(KeyError):
        obj.map('array')[obj.map('array').capacity()] = 666

    # Query the full map
    for i in range(obj.map('array').capacity()):
        assert obj.map('array')[i].value == i

    # Update an existing value
    obj.map('array')[4] = 666
    assert obj.map('array')[4].value == 666

    # Clear the map
    for i in range(obj.map('array').capacity()):
        del obj.map('array')[i]
    assert len(obj.map('array')) == obj.map('array').capacity()

    # Try to query the empty map
    for i in range(obj.map('array').capacity()):
        obj.map('array')[i] == 0

def test_percpu_array(init: ProjectInit):
    """
    Test BPF_PERCPU_ARRAY.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    percpu_array = obj.map('percpu_array')

    percpu_array.register_value_type(ct.c_int)
    # It should be impossible to change the key type
    with pytest.raises(NotImplementedError):
        obj.map('array').register_key_type(ct.c_int)

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

def test_prog_array(init: ProjectInit):
    """
    Test BPF_PROG_ARRAY.
    """
    pytest.skip('TODO')

def test_perf_event_array(init: ProjectInit):
    """
    Test BPF_PERF_EVENT_ARRAY.
    """
    pytest.skip('TODO')

def test_stack_trace(init: ProjectInit):
    """
    Test BPF_STACK_TRACE.
    """
    pytest.skip('TODO')

def test_cgroup_array(init: ProjectInit):
    """
    Test BPF_CGROUP_ARRAY.
    """
    pytest.skip('TODO')

def test_lpm_trie(init: ProjectInit):
    """
    Test BPF_LPM_TRIE.
    """
    pytest.skip('TODO')

def test_array_of_maps(init: ProjectInit):
    """
    Test BPF_ARRAY_OF_MAPS.
    """
    pytest.skip('TODO')

def test_hash_of_maps(init: ProjectInit):
    """
    Test BPF_HASH_OF_MAPS.
    """
    pytest.skip('TODO')

def test_devmap(init: ProjectInit):
    """
    Test BPF_DEVMAP.
    """
    pytest.skip('TODO')

def test_sockmap(init: ProjectInit):
    """
    Test BPF_SOCKMAP.
    """
    pytest.skip('TODO')

def test_cpumap(init: ProjectInit):
    """
    Test BPF_CPUMAP.
    """
    pytest.skip('TODO')

def test_xskmap(init: ProjectInit):
    """
    Test BPF_XSKMAP.
    """
    pytest.skip('TODO')

def test_sockhash(init: ProjectInit):
    """
    Test BPF_SOCKHASH.
    """
    pytest.skip('TODO')

def test_cgroup_storage(init: ProjectInit):
    """
    Test BPF_CGROUP_STORAGE.
    """
    pytest.skip('TODO')

def test_reuseport_sockarray(init: ProjectInit):
    """
    Test BPF_REUSEPORT_SOCKARRAY.
    """
    pytest.skip('TODO')

def test_percpu_cgroup_storage(init: ProjectInit):
    """
    Test BPF_PERCPU_CGROUP_STORAGE.
    """
    pytest.skip('TODO')

def test_queue(init: ProjectInit):
    """
    Test BPF_QUEUE.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    queue = obj.map('queue')

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

def test_stack(init: ProjectInit):
    """
    Test BPF_STACK.
    """
    so = init.compile_bpf_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c'))
    obj = BPFObject(so, True, True)

    stack = obj.map('stack')

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

def test_sk_storage(init: ProjectInit):
    """
    Test BPF_SK_STORAGE.
    """
    pytest.skip('TODO')

def test_devmap_hash(init: ProjectInit):
    """
    Test BPF_DEVMAP_HASH.
    """
    pytest.skip('TODO')

def test_struct_ops(init: ProjectInit):
    """
    Test BPF_STRUCT_OPS.
    """
    pytest.skip('TODO')

