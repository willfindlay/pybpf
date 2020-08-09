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

import pytest

from pybpf.object import BPFObjectBuilder
from pybpf.maps import create_map
from pybpf.utils import project_path, which

BPF_SRC = project_path('tests/bpf_src')

def test_ringbuf(builder: BPFObjectBuilder):
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
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'ringbuf.bpf.c')).build()

    with pytest.raises(KeyError):
        @obj.ringbuf_callback('ringbuf3', ct.c_int)
        def _callback(ctx, data, size):
            print('unreachable!')

def test_maps_smoke(builder: BPFObjectBuilder):
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    EXPECTED_MAP_COUNT = 7

    if len(obj.maps) > EXPECTED_MAP_COUNT:
        pytest.xfail(f'EXPECTED_MAP_COUNT should be updated to {len(obj.maps)}')

    assert len(obj.maps) == EXPECTED_MAP_COUNT

def test_bad_map(builder: BPFObjectBuilder):
    obj = builder.generate_skeleton(os.path.join(BPF_SRC, 'maps.bpf.c')).build()

    with pytest.raises(KeyError):
        obj['foo']

def test_hash(builder: BPFObjectBuilder):
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
        obj['hash'][5] = 666

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
    pytest.skip('TODO')

def test_lru_hash(builder: BPFObjectBuilder):
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
    for i in range(obj['lru_hash'].capacity()):
        obj['lru_hash'][i] = i

    assert len(obj['lru_hash']) <= obj['lru_hash'].capacity()

    for i, v in obj['lru_hash'].items():
        assert i.value == v.value

    obj['lru_hash'].clear()

    assert len(obj['lru_hash']) == 0

def test_lru_percpu_hash(builder: BPFObjectBuilder):
    pytest.skip('TODO')

def test_array(builder: BPFObjectBuilder):
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
        obj['array'][5] = 666

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
    pytest.skip('TODO')

    # Register
    #with pytest.raises(NotImplementedError):
    #    obj['array'].register_key_type(ct.c_int)
    #obj['array'].register_value_type(ct.c_int)
    #with pytest.raises(NotImplementedError):
    #    obj['percpu_array'].register_key_type(ct.c_int)
    #obj['percpu_array'].register_value_type(ct.c_int)
