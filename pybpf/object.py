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

from __future__ import annotations
import os
import shutil
import ctypes as ct
import subprocess
import atexit
from typing import List, Optional, Callable

from pybpf.lib import create_skeleton_lib, _RINGBUF_CB_TYPE
from pybpf.utils import kversion, arch, which, assert_exists, module_path, cerr, force_bytes, FILESYSTEMENCODING

SKEL_OBJ_IN = module_path('cc/libpybpf.c.in')

class BPFObject:
    """
    A BPF object. This class should not be instantiated directly.
    Instead, create it using BPFObjectBuilder.
    """
    def __init__(self, skeleton_obj_file: str, bump_rlimit: bool, autoload: bool):
        self._lib = create_skeleton_lib(ct.CDLL(skeleton_obj_file))

        self._bump_rlimit = bump_rlimit
        self._bpf_loaded = False
        self._cleaned_up = False

        self.maps = {}
        self._ringbuf_mgr = None

        if autoload:
            # Auto load BPF program
            self._bpf_autoload()

    def ringbuf_callback(self, name, data_type: Optional[ct.Structure] = None):
        """
        The ringbuf map is the canonical way to pass per-event data to
        userspace. This decorator marks a function as a callback for events
        from @ringbuf.

        @ringbuf must be declared as a ringbuf map in the BPF program.

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
        return self.get_map(name).callback(data_type)

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
                    '@BPFObject["map"].callback(DataType).')
        return self._lib.ring_buffer__consume(self._ringbuf_mgr)

    def ringbuf_poll(self, timeout: int = -1):
        """
        Poll for events from all open ring buffers, calling the provided
        callback for each ringbuffer. @timeout specifies a polling timeout in
        ms.  By default, polling continues indefinitely.
        """
        if not self._ringbuf_mgr:
            raise Exception('No ring buffers to consume. '
                    'Register ring buffers using '
                    '@BPFObject["map"].callback(DataType).')
        return self._lib.ring_buffer__poll(self._ringbuf_mgr, timeout)

    def load_bpf(self, initialization_function: Callable[['Obj'], None] = lambda obj: None) -> None:
        """
        Load BPF programs, bumping rlimit to infinity if configured to do so,
        and calling @initialization_function(obj) before loading takes place.
        Calling this manually is only necessary if BPFObject is _not_ set to
        autload BPF programs. This may be desirable if an initialization_function
        is necessary, for example to set .rodata, .bss, or .data segments.
        """
        if self._bpf_loaded:
            raise Exception('BPF programs have already been loaded. '
                    'This error may caused by trying to manually load BPF '
                    'programs after the BPFObject has been set to autoload BPF '
                    'programs.')

        # Raise an OSError if we don't have root privileges
        self._force_root()

        # Bump rlimit to infinity so we can load out BPF program
        # The user might prefer to do this manually, so make this step optional
        if self._bump_rlimit:
            ret = self._lib.bump_memlock_rlimit()
            if ret != 0:
                raise Exception(f'Failed to bump rlimit to infinity: {cerr(ret)}')

        # Open the BPF program
        self.bpf = self._lib.pybpf_open()
        if self.bpf == 0:
            raise Exception(f'Failed to open BPF object: {cerr()}')

        # Get the raw BPF object
        self.obj = self._lib.get_bpf_object(self.bpf)
        if self.obj == 0:
            raise Exception(f'Failed to get BPF object: {cerr()}')

        # Call the provided initialization function
        initialization_function(self.obj)

        # Load the BPF object
        ret = self._lib.pybpf_load(self.bpf)
        if ret != 0:
            raise Exception(f'Failed to load BPF object: {cerr(ret)}')

        # Attach BPF programs
        ret = self._lib.pybpf_attach(self.bpf)
        if ret != 0:
            raise Exception(f'Failed to attach BPF programs: {cerr(ret)}')

        # Create maps
        from pybpf.maps import create_map
        for _map in self._lib.obj_maps(self.obj):
            map_mtype = self._lib.bpf_map__type(_map)
            map_fd = self._lib.bpf_map__fd(_map)
            map_name = self._lib.bpf_map__name(_map).decode(FILESYSTEMENCODING)
            map_ksize = self._lib.bpf_map__key_size(_map)
            map_vsize = self._lib.bpf_map__value_size(_map)
            max_entries = self._lib.bpf_map__max_entries(_map)

            self.maps[map_name] = create_map(self, map_fd, map_mtype, map_ksize, map_vsize, max_entries)

        # Make sure we clean up libbpf memory when the program exits
        atexit.register(self._cleanup)

        self._bpf_loaded = True

    def get_map(self, name):
        try:
            return self.maps[name]
        except KeyError:
            raise KeyError(f'No such map "{name}"') from None

    def _cleanup(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True
        # Destroy libbpf objects
        self._lib.pybpf_destroy(self.bpf)
        # Free ring buffers
        if self._ringbuf_mgr:
            self._lib.ring_buffer__free(self._ringbuf_mgr)
        self._bpf_loaded = False

    def _bpf_autoload(self) -> None:
        self.load_bpf()

    def _force_root(self) -> None:
        if os.geteuid() != 0:
            raise OSError('You neep root privileges to load BPF programs into the kernel.')

    def __getitem__(self, key: str) -> Optional[MapBase, Ringbuf]:
        if key not in self.maps:
            self.maps[key] = self.get_map(key)
        return self.maps[key]

    def __len__(self):
        return len(self.maps)

    def __delitem__(self, key):
        del self.maps[key]

    def __iter__(self):
        return self.maps.__iter__()

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
    PYBPF_H     = module_path('cc/pybpf.bpf.h')

    def __init__(self):
        self._vmlinux_kversion_h : str = None
        self._vmlinux_h          : str = None
        self._bpf_obj_file       : str = None
        self._skeleton           : str = None
        self._skeleton_obj_file  : str = None
        self._bump_rlimit        : bool = True
        self._autoload           : bool = True

        self.bpf_object = None

        self.OUTDIR = os.path.abspath(self.OUTDIR)

        os.makedirs(self.OUTDIR, exist_ok=True)

    def use_existing_skeleton(self, skeleton_obj_file: str) -> BPFObjectBuilder:
        """
        For use in production.  Use an existing skeleton object file
        @skeleton_obj_file rather than generating a new one.

        This skeleton file should either be shipped with your application or
        built when it is first run.
        """
        try:
            assert_exists(skeleton_obj_file)
        except FileNotFoundError:
            skeleton_obj_file = os.path.join(self.OUTDIR, skeleton_obj_file)
        try:
            assert_exists(skeleton_obj_file)
        except FileNotFoundError:
            raise FileNotFoundError(f'Specified skeleton object file {skeleton_obj_file} does not exist.') from None

        self._skeleton_obj_file = os.path.abspath(skeleton_obj_file)

        return self

    def generate_skeleton(self, bpf_src: str) -> BPFObjectBuilder:
        """
        Generate the BPF skeleton object for @bpf_src.
        This function combines the following:
        ```
            self._generate_vmlinux(bpf_src)
            self._generate_bpf_obj_file(bpf_src)
            self._generate_bpf_skeleton()
            self._generate_skeleton_obj_file()
        ```
        which may be called individually for greater control.
        """
        bpf_src = os.path.abspath(bpf_src)

        self._generate_vmlinux(bpf_src)
        self._generate_bpf_obj_file(bpf_src)
        self._generate_bpf_skeleton()
        self._generate_skeleton_obj_file()

        return self

    def _generate_vmlinux(self, bpf_src: str) -> BPFObjectBuilder:
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
        bpf_src_dir = os.path.dirname(bpf_src)
        self._vmlinux_kversion_h = os.path.join(bpf_src_dir, f'vmlinux_{kversion()}.h')
        self._vmlinux_h = os.path.join(bpf_src_dir, 'vmlinux.h')

        try:
            bpftool = [which('bpftool')]
        except FileNotFoundError:
            raise OSError('bpftool not found on system. '
                    'You can install bpftool from linux/tools/bpf/bpftool '
                    'in your kernel sources.') from None

        try:
            assert_exists(self.VMLINUX_BTF)
        except FileNotFoundError:
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

        # TODO maybe move this into a CLI bootstrapping tool?
        shutil.copy(self.PYBPF_H, bpf_src_dir)

        return self

    def _generate_bpf_obj_file(self, bpf_src: str, cflags: List[str] = []) -> BPFObjectBuilder:
        """
        Compile the BPF object file from @bpf_src using clang and llvm-strip.
        Optional flags may be passed to clang using @cflags.

        Requires:
            - A recent clang in $PATH.
            - A recent llvm-strip in $PATH.
        """
        try:
            assert_exists(bpf_src)
        except FileNotFoundError:
            raise FileNotFoundError(f'Specified source file {bpf_src} does not exist.') from None

        if not self._vmlinux_h or not self._vmlinux_kversion_h:
            raise Exception('Please generate vmlinux.h first with BPFObjectBuilder.generate_vmlinux().')

        obj_file = os.path.join(self.OUTDIR, os.path.splitext(os.path.basename(bpf_src))[0] + '.o')

        try:
            clang = [which('clang')]
        except FileNotFoundError:
            raise FileNotFoundError('clang not found on system. '
                    'Please install clang and try again.') from None

        auto_includes = module_path('cc/auto_includes.bpf.h')

        clang_args = cflags + f'-g -O2 -target bpf -D__TARGET_ARCH_{arch()} -I{self.OUTDIR}'.split() + f'-c {bpf_src} -o {obj_file}'.split()

        try:
            llvm_strip = [which('llvm-strip'), '-g', obj_file]
        except FileNotFoundError:
            raise FileNotFoundError('llvm-strip not found on system. '
                    'Please install llvm-strip and try again.') from None

        subprocess.check_call(clang + clang_args, stdout=subprocess.DEVNULL)
        subprocess.check_call(llvm_strip, stdout=subprocess.DEVNULL)

        self._bpf_obj_file = obj_file

        return self

    def _generate_bpf_skeleton(self) -> BPFObjectBuilder:
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
        except FileNotFoundError:
            raise FileNotFoundError('bpftool not found on system. '
                    'You can install bpftool from linux/tools/bpf/bpftool '
                    'in your kernel sources.') from None

        bpftool_args = f'gen skeleton {self._bpf_obj_file}'.split()

        with open(skel_h, 'w+') as f:
            subprocess.check_call(bpftool + bpftool_args, stdout=f)

        self._skeleton = skel_h

        return self

    def _generate_skeleton_obj_file(self, cflags: List[str] = []) -> BPFObjectBuilder:
        """
        Generate the source code for the skeleton object file
        and compile it into a shared object using gcc.

        Requires:
            - A recent gcc in $PATH.
        """
        try:
            gcc = [which('gcc')]
        except FileNotFoundError:
            raise FileNotFoundError('gcc not found on system. '
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

    def set_bump_rlimit(self, bump_rlimit: bool) -> BPFObjectBuilder:
        """
        Decide whether the BPF program should implicitly bump rlimit to
        infinity.  This option defaults to True. Disabling it allows you more
        control, but you will need to remember to bump rlimit manually.
        """
        self._bump_rlimit = bump_rlimit

        return self

    def set_autoload(self, autoload: bool) -> BPFObjectBuilder:
        """
        Decide whether the BPF program should automatically load BPF programs.
        This option defaults to True. Disabling it gives you more control,
        but requires that you remember to call obj.load_bpf after building.
        """
        self._autoload = autoload

        return self

    def build(self) -> BPFObject:
        """
        Build the BPF object. Requires a skeleton object file to be either
        generated or provided using the
        `BPFObjectBuilder.use_existing_skeleton('my_program.skel.so')` shortcut.
        """
        if not self._skeleton_obj_file:
            raise Exception('You must build or provide an existing skeleton object file.')

        bpf_object = BPFObject(self._skeleton_obj_file, self._bump_rlimit, self._autoload)

        self.__init__()
        self.bpf_object = bpf_object

        return bpf_object
