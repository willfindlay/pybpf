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

    2020-Aug-29  William Findlay  Created this.
"""

import os
import inspect
import subprocess
import logging
import datetime as dt
from dataclasses import dataclass
from typing import Optional, List, Tuple

from pybpf.skeleton import generate_skeleton
from pybpf.utils import kversion, which, assert_exists, drop_privileges, strip_full_extension, arch, module_path

logger = logging.getLogger(__name__)

TEMPLATES_DIR = module_path('templates')

def get_caller_dir():
    try:
        cf = inspect.stack()[-1]
    except IndexError:
        raise Exception("Unable to find caller's directory")
    return os.path.dirname(os.path.abspath(cf.filename))

class Bootstrap:
    VMLINUX_BTF = '/sys/kernel/btf/vmlinux'

    @classmethod
    @drop_privileges
    def bootstrap(cls, bpf_src: str, outdir: Optional[str] = None) -> Tuple[str, str]:
        """
        Combines Bootstrap.generate_vmlinux(), Bootstrap.compile_bpf(), and Bootstrap.generate_skeleton() into one step.
        Returns the skeleton class filename and the name of the skeleton class.
        """
        assert os.path.isfile(bpf_src)

        bpf_dir = os.path.dirname(bpf_src)

        assert os.path.isdir(bpf_dir)

        vmlinux = cls.generate_vmlinux(bpf_dir)
        obj = cls.compile_bpf(bpf_src, outdir=outdir)
        skel_file, skel_cls = cls.generate_skeleton(obj, outdir=outdir)

        return skel_file, skel_cls

    @staticmethod
    @drop_privileges
    def generate_vmlinux(bpfdir: Optional[str] = None, overwrite: bool = False) -> str:
        """
        Use bpftool to generate the @bpfdir/vmlinux.h header file symlink for that corresponds with the BTF info for the current kernel. Unless @overwrite is true, existing vmlinux files will not be updated. Only the symbolic link will be updated.
        """
        if not bpfdir:
            bpfdir = os.path.join(get_caller_dir(), 'bpf')
        if not os.path.exists(bpfdir):
            raise FileNotFoundError(f'No such directory {bpfdir}')

        bpfdir = os.path.abspath(bpfdir)

        vmlinux_kversion_h = os.path.join(bpfdir, f'vmlinux_{kversion()}.h')
        vmlinux_h = os.path.join(bpfdir, 'vmlinux.h')

        if (not os.path.exists(vmlinux_kversion_h)) or overwrite:
            try:
                bpftool = [which('bpftool')]
            except FileNotFoundError:
                raise OSError(
                    'bpftool not found on system. '
                    'You can install bpftool from linux/tools/bpf/bpftool '
                    'in your kernel sources.'
                ) from None

            try:
                assert_exists(Bootstrap.VMLINUX_BTF)
            except FileNotFoundError:
                raise OSError(
                    f'BTF file {Bootstrap.VMLINUX_BTF} does not exist. '
                    'Please build your kernel with CONFIG_DEBUG_INFO_BTF=y '
                    'or set Bootstrap.VMLINUX_BTF to the correct location.'
                ) from None

            bpftool_args = f'btf dump file {Bootstrap.VMLINUX_BTF} format c'.split()

            with open(vmlinux_kversion_h, 'w+') as f:
                subprocess.check_call(bpftool + bpftool_args, stdout=f)

        try:
            os.unlink(vmlinux_h)
        except FileNotFoundError:
            pass
        os.symlink(vmlinux_kversion_h, vmlinux_h)

        logger.info(f'Generated {vmlinux_h}')

        return vmlinux_h

    @staticmethod
    @drop_privileges
    def compile_bpf(bpf_src: str, outdir: Optional[str] = None, cflags: List[str] = []) -> str:
        """
        Generate the BPF object file for @bpf_src and place it in @outdir.
        """
        if not outdir:
            outdir = get_caller_dir()

        bpf_src = os.path.abspath(bpf_src)
        outdir = os.path.abspath(outdir)

        # Check for source file
        try:
            assert_exists(bpf_src)
        except FileNotFoundError:
            raise FileNotFoundError(f'Specified source file {bpf_src} does not exist.') from None

        bpf_dir = os.path.dirname(bpf_src)

        # Check for vmlinux.h
        try:
            assert_exists(os.path.join(bpf_dir, 'vmlinux.h'))
        except FileNotFoundError:
            raise FileNotFoundError('Please generate vmlinux.h first with generate_vmlinux().') from None

        obj_file = os.path.join(bpf_dir, strip_full_extension(os.path.basename(bpf_src)) + '.bpf.o')

        # Check for clang
        try:
            clang = [which('clang')]
        except FileNotFoundError:
            raise FileNotFoundError('clang not found on system. '
                    'Please install clang and try again.') from None

        clang_args = cflags + f'-g -O2 -target bpf -D__TARGET_ARCH_{arch()}'.split() + f'-c {bpf_src} -o {obj_file}'.split()

        # Check for llvm-strip
        try:
            llvm_strip = [which('llvm-strip'), '-g', obj_file]
        except FileNotFoundError:
            raise FileNotFoundError('llvm-strip not found on system. '
                    'Please install llvm-strip and try again.') from None

        # Compile BPF program
        logger.info(f'Compiling BPF program {bpf_src} -> {obj_file}')
        try:
            subprocess.check_call(clang + clang_args, stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            raise Exception("Failed to compile BPF program") from None

        # Strip symbols from BPF program
        logger.info(f'Stripping symbols from BPF program {obj_file}')
        try:
            subprocess.check_call(llvm_strip, stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            raise Exception("Failed to strip symbols from BPF program") from None

        return obj_file

    @staticmethod
    @drop_privileges
    def generate_skeleton(bpf_obj_path: str, outdir: Optional[str] = None) -> Tuple[str, str]:
        """
        Regenerate the python skeleton file for the @bpf_obj_path.  The file will be generated in the same directory as the caller or @outdir if specified. Returns the skeleton class filename and the name of the skeleton class.
        """
        if not outdir:
            outdir = get_caller_dir()
        return generate_skeleton(bpf_obj_path, outdir)

    @dataclass
    class ProjectBuilder:
        """
        A builder that can be used to create a new pybpf project.
        """
        author_name: str
        project_name: str
        author_email: Optional[str] = None
        project_dir: Optional[str] = None
        project_git: Optional[str] = None
        project_description: Optional[str] = None
        overwrite_existing: bool = False

        def __post_init__(self):
            now = dt.datetime.now()
            self.year, self.month, self.day = now.strftime('%Y %b %d').split()

        def build(self):
            """
            Build the pybpf project.
            """
            # Apply sensible defaults
            if self.author_email is None:
                self.author_email = ''
            if self.project_dir is None:
                self.project_dir = '.'
            if self.project_git is None:
                self.project_git = ''
            if self.project_description is None:
                self.project_description = ''

            # Make sure project_dir is an absolute path
            self.project_dir = os.path.abspath(self.project_dir)

            # Create project directory
            try:
                os.makedirs(self.project_dir, exist_ok=False)
            except FileExistsError:
                if len(os.listdir(self.project_dir)) and not self.overwrite_existing:
                    raise Exception(f'Refusing to overwrite non-empty project directory {self.project_dir}') from None

            logger.info(f'Creating a new pybpf project in {self.project_dir}...')

            # Copy template files over
            for depth, (root, dirs, files) in enumerate(os.walk(TEMPLATES_DIR)):
                for _file in files:
                    tf = os.path.join(root, _file)

                    if depth:
                        subdirs = os.path.join(*root.split(os.sep)[-depth:])
                    else:
                        subdirs = ''
                    od = os.path.join(self.project_dir, subdirs)
                    os.makedirs(od, exist_ok=True)

                    of = os.path.join(od, _file)

                    logger.info(f'Creating {of}...')

                    # Read from template file
                    with open(tf, 'r') as f:
                        text = f.read()

                    # Sub in as appropriate
                    text = text.replace('PROJECT_NAME', self.project_name)
                    text = text.replace(
                        'PROJECT_DESCRIPTION', self.project_description
                    )
                    text = text.replace('AUTHOR_NAME', self.author_name)
                    text = text.replace('AUTHOR_EMAIL', self.author_email)
                    text = text.replace('YEAR', self.year)
                    text = text.replace('MONTH', self.month)
                    text = text.replace('DAY', self.day)

                    # Write to outfile
                    with open(of, 'w+') as f:
                        f.write(text)

            logger.info(f'{self.project_dir} has been bootstrapped successfully!')
