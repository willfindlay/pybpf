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
import atexit
from typing import List, Optional, Callable

from pybpf.lib import create_skeleton_lib, _RINGBUF_CB_TYPE
from pybpf.utils import kversion, arch, which, assert_exists, project_path, cerr, force_bytes

SKEL_OBJ_IN = project_path('pybpf/cc/libpybpf.c.in')

class BPFObject:
    """
    A BPF object. This class should not be instantiated directly.
    Instead, create it using BPFObjectBuilder.
    """
    def __init__(self, skeleton_obj_file: str, bump_rlimit: bool = True):
        self.lib = create_skeleton_lib(ct.CDLL(skeleton_obj_file))

        self._ringbuf_mgr = None
        self._cbs = {}

        # Auto load BPF program
        self._bpf_autoload(bump_rlimit)

    def ringbuf_callback(self, ringbuf: str, data_type: Optional[ct.Structure] = None) -> Callable:
        """
        The ringbuf map is the canonical way to pass per-event data to
        userspace. This decorator marks a function as a callback for events
        from @ringbuf.

        @ringbuf must be declared as a ringbuf map in the BPF program.

        @data_type may be specified to automatically convert the data pointer to
        the appropriate ctype. Otherwise, this conversion must be done manually.

        The decorated function must have the following signature:
        ```
            def callback(ctx: Any, data: ct.c_void_p, size: int):
                # Do work
        ```

        Optionally, the function may return a non-zero integer to indicate that
        polling should be stopped.
        """
        if not self.obj:
            raise Exception(f'No BPF object loaded!')

        # Look up ringbuf fd by its name
        ringbuf = force_bytes(ringbuf)
        ringbuf_fd = self.lib.bpf_object__find_map_fd_by_name(self.obj, ringbuf)
        if ringbuf_fd < 0:
            raise Exception(f'Failed to get a file descriptor for {ringbuf}: {cerr(ringbuf_fd)}')

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
            self._open_ringbuf(ringbuf_fd, wrapper)
            return wrapper
        return inner

    def ringbuf_consume(self):
        """
        Consume all open ringbuf buffers, regardless of whether or not they
        currently contain event data. As this method avoids making calls to
        epoll_wait, it is best for use cases where low latency is desired, but
        it can impact performance. If you are unsure, use ring_buffer_poll
        instead.
        """
        if not self._ringbuf_mgr:
            raise Exception('No ring buffers to consume. '
                    'Register ring buffers using '
                    '@BPFObject.ringbuf_callback("map", DataTypeStruct).')
        return self.lib.ring_buffer__consume(self._ringbuf_mgr)

    def ringbuf_poll(self, timeout: int = -1):
        """
        Poll for events from all open ring buffers, calling the provided
        callback for each ringbuffer. @timeout specifies a polling timeout in
        ms.  By default, polling continues indefinitely.
        """
        if not self._ringbuf_mgr:
            raise Exception('No ring buffers to poll. '
                    'Register ring buffers using '
                    '@BPFObject.ringbuf_callback("map", DataTypeStruct).')
        return self.lib.ring_buffer__poll(self._ringbuf_mgr, timeout)

    def _open_ringbuf(self, map_fd: ct.c_int, func: Callable, ctx: ct.c_void_p = None) -> None:
        # Cast func as _RINGBUF_CB_TYPE
        func = _RINGBUF_CB_TYPE(func)
        # Handle case where we don't have a manager yet
        if not self._ringbuf_mgr:
            self._ringbuf_mgr = self.lib.ring_buffer__new(map_fd, func, ctx, None)
            if not self._ringbuf_mgr:
                raise Exception(f'Failed to create new ring buffer manager: {cerr()}')
        # Handle case where we already have a manager
        else:
            ret = self.lib.ring_buffer__add(self._ringbuf_mgr, map_fd, func, ctx)
            if ret != 0:
                raise Exception(f'Failed to add ringbuf to ring buffer manager: {cerr(ret)}')
        # Keep a refcnt so that our function doesn't get cleaned up
        self._cbs[ct.addressof(func)] = func

    def _cleanup(self) -> None:
        # Destroy libbpf objects
        self.lib.pybpf_destroy(self.bpf)
        if self._ringbuf_mgr:
            self.lib.ring_buffer__free(self._ringbuf_mgr)

    def _bpf_autoload(self, bump_rlimit: bool = True) -> None:
        # Raise an exception if we don't have root privileges
        self._force_root()

        # Bump rlimit to infinity so we can load out BPF program
        # The user might prefer to do this manually, so make this step optional
        if bump_rlimit:
            ret = self.lib.bump_memlock_rlimit()
            if ret != 0:
                raise Exception(f'Failed to bump rlimit to infinity: {cerr(ret)}')

        # Open, load, and attach the BPF object
        self.bpf = self.lib.pybpf_open()
        if self.bpf == 0:
            raise Exception(f'Failed to open BPF object: {cerr()}')
        self.obj = self.lib.get_bpf_object(self.bpf)
        if self.obj == 0:
            raise Exception(f'Failed to get BPF object: {cerr()}')
        ret = self.lib.pybpf_load(self.bpf)
        if ret != 0:
            raise Exception(f'Failed to load BPF object: {cerr(ret)}')
        ret = self.lib.pybpf_attach(self.bpf)
        if ret != 0:
            raise Exception(f'Failed to attach BPF programs: {cerr(ret)}')

        # Make sure we clean up libbpf memory when the program exits
        atexit.register(self._cleanup)

    def _force_root(self) -> None:
        if os.geteuid() != 0:
            raise OSError('You neep root privileges to load BPF programs into the kernel.')

class BPFObjectBuilder:
    """
    Builds a BPF object.

    For development, make the following calls in sequence:
    ```
        builder = BPFObjectBuilder()
        builder.generate_vmlinux()
        builder.generate_bpf_obj_file()
        builder.generate_skeleton()
        builder.generate_skeleton_obj_file()
        obj = builder.build()
    ```

    For production, you can bootstrap using the generated skeleton object file:
    ```
        obj = BPFObjectBuilder().use_existing_skeleton('my_program.skel.so').build()
    ```
    """

    VMLINUX_BTF = '/sys/kernel/btf/vmlinux'
    OUTDIR      = '.output'

    def __init__(self):
        self._vmlinux_kversion_h : str = None
        self._vmlinux_h          : str = None
        self._bpf_obj_file       : str = None
        self._skeleton           : str = None
        self._skeleton_obj_file  : str = None
        self._bump_rlimit        : bool = True

        os.makedirs(self.OUTDIR, exist_ok=True)

    def use_existing_skeleton(self, skeleton_obj_file: str) -> 'Self':
        """
        For use in production.  Use an existing skeleton object file
        @skeleton_obj_file rather than generating a new one.

        This skeleton file should either be shipped with your application or
        built when it is first run.

        Allows the builder to skip the steps:
            - generate_vmlinux()
            - generate_bpf_obj_file()
            - generate_skeleton()
            - generate_skeleton_obj_file()
        """
        try:
            assert_exists(skeleton_obj_file)
        except OSError:
            skeleton_obj_file = os.path.join(self.OUTDIR, skeleton_obj_file)
        try:
            assert_exists(skeleton_obj_file)
        except OSError:
            raise ValueError(f'Specified skeleton object file {skeleton_obj_file} does not exist.') from None

        self._skeleton_obj_file = skeleton_obj_file

        return self

    def generate_vmlinux(self) -> 'Self':
        """
        Use bpftool to generate the vmlinux.h header file symlink for
        that corresponds with the BTF info for the current kernel.

        Creates a file "{BPFObjectBuilder.OUTDIR}/vmlinux_{kversion()}.h"
        and a symbolic link "{BPFObjectBuilder.OUTDIR}/vmlinux.h" that
        points to it.

        Requires:
            - A recent version of bpftool in your $PATH.
            - A kernel compiled with CONFIG_DEBUG_INFO_BTF=y.
            - BTF vmlinux located at BPFObjectBuilder.VMLINUX_BTF
              ('/sys/kernel/btf/vmlinux' by default)
        """
        self._vmlinux_kversion_h = os.path.join(self.OUTDIR, f'vmlinux_{kversion()}.h')
        self._vmlinux_h = os.path.join(self.OUTDIR, 'vmlinux.h')

        try:
            bpftool = [which('bpftool')]
        except OSError:
            raise OSError('bpftool not found on system. '
                    'You can install bpftool from linux/tools/bpf/bpftool '
                    'in your kernel sources.') from None

        try:
            assert_exists(self.VMLINUX_BTF)
        except OSError:
            raise OSError(f'BTF file {self.VMLINUX_BTF} does not exist. '
                    'Please build your kernel with CONFIG_DEBUG_INFO_BTF=y '
                    'or set BPFObjectBuilder.VMLINUX_BTF to the correct location.') from None

        bpftool_args = f'btf dump file {self.VMLINUX_BTF} format c'.split()

        with open(self._vmlinux_kversion_h, 'w+') as f:
            subprocess.check_call(bpftool + bpftool_args, stdout=f)

        try:
            os.unlink(self._vmlinux_h)
        except FileNotFoundError:
            pass
        os.symlink(self._vmlinux_kversion_h, self._vmlinux_h)

        return self

    def generate_bpf_obj_file(self, bpf_src: str, cflags: List[str] = []) -> 'Self':
        """
        Compile the BPF object file from @bpf_src using clang and llvm-strip.
        Optional flags may be passed to clang using @cflags.

        Requires:
            - A recent clang in $PATH.
            - A recent llvm-strip in $PATH.
        """
        try:
            assert_exists(bpf_src)
        except OSError:
            raise ValueError(f'Specified source file {bpf_src} does not exist.') from None

        if not self._vmlinux_h or not self._vmlinux_kversion_h:
            raise ValueError('Please generate vmlinux.h first with BPFObjectBuilder.generate_vmlinux().')

        obj_file = os.path.join(self.OUTDIR, os.path.splitext(os.path.basename(bpf_src))[0] + '.o')

        try:
            clang = [which('clang')]
        except OSError:
            raise OSError('clang not found on system. '
                    'Please install clang and try again.') from None

        clang_args = cflags + f'-g -O2 -target bpf -D__TARGET_ARCH_{arch()} -I{self.OUTDIR}'.split() + f'-c {bpf_src} -o {obj_file}'.split()

        try:
            llvm_strip = [which('llvm-strip'), '-g', obj_file]
        except OSError:
            raise OSError('llvm-strip not found on system. '
                    'Please install llvm-strip and try again.') from None

        subprocess.check_call(clang + clang_args, stdout=subprocess.DEVNULL)
        subprocess.check_call(llvm_strip, stdout=subprocess.DEVNULL)

        self._bpf_obj_file = obj_file

        return self

    def generate_bpf_skeleton(self) -> 'Self':
        """
        Use bpftool to generate the .skel.h file for the builder's
        bpf_obj_file.

        Requires:
            - A recent version of bpftool in your $PATH.
            - A kernel compiled with CONFIG_DEBUG_INFO_BTF=y.
        """
        skel_h = os.path.splitext(self._bpf_obj_file)[0] + '.skel.h'

        try:
            bpftool = [which('bpftool')]
        except OSError:
            raise OSError('bpftool not found on system. '
                    'You can install bpftool from linux/tools/bpf/bpftool '
                    'in your kernel sources.') from None

        bpftool_args = f'gen skeleton {self._bpf_obj_file}'.split()

        with open(skel_h, 'w+') as f:
            subprocess.check_call(bpftool + bpftool_args, stdout=f)

        self._skeleton = skel_h

        return self

    def generate_skeleton_obj_file(self, cflags: List[str] = []) -> 'Self':
        """
        Generate the source code for the skeleton object file
        and compile it into a shared object using gcc.

        Requires:
            - A recent gcc in $PATH.
        """
        try:
            gcc = [which('gcc')]
        except OSError:
            raise OSError('gcc not found on system. '
                    'Please install gcc and try again.') from None

        with open(SKEL_OBJ_IN, 'r') as f:
            skel = f.read()

        skel_c = os.path.splitext(self._bpf_obj_file)[0] + '.skel.c'
        skel_so = os.path.splitext(self._bpf_obj_file)[0] + '.skel.so'

        prefix = os.path.splitext(os.path.basename(self._bpf_obj_file))[0].replace('.', '_').replace('-', '_')
        skel = skel.replace('SKELETON_H', self._skeleton)
        skel = skel.replace('BPF', prefix)

        with open(skel_c, 'w+') as f:
            f.write(skel)

        gcc_args = cflags + f'-shared -lbpf -lelf -lz -O2 -o {skel_so} {skel_c}'.split()

        self._skeleton_obj_file = skel_so

        subprocess.check_call(gcc + gcc_args, stdout=subprocess.DEVNULL)

        return self

    def set_bump_rlimit(self, bump_rlimit: bool) -> 'Self':
        """
        Decide whether the BPF program should implicitly bump rlimit to
        infinity.  This option defaults to True. Disabling it allows you more
        control, but you will need to remember to bump rlimit manually.
        """
        self._bump_rlimit = bump_rlimit

        return self

    def build(self) -> BPFObject:
        """
        Build the BPF object. Requires a skeleton object file to be either
        generated or provided using the
        `BPFObjectBuilder.use_existing_skeleton('my_program.skel.so')` shortcut.
        """
        if not self._skeleton_obj_file:
            raise Exception('You must build or provide an existing skeleton object file.')

        bpf_object = BPFObject(self._skeleton_obj_file, bump_rlimit=self._bump_rlimit)

        self.__init__()

        return bpf_object
