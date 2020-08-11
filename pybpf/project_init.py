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

    2020-Aug-15  William Findlay  Created this.
"""
import os
import sys
import subprocess
import logging
import datetime as dt
import toml
from typing import Optional

from pybpf.utils import (
    module_path,
    drop_privileges,
    which,
    kversion,
    arch,
    assert_exists,
    strip_full_extension,
    find_file_up_tree
)

logger = logging.getLogger(__name__)

TEMPLATES_DIR = module_path('templates')
SKEL_OBJ_IN = module_path('cc/libpybpf.c.in')


class ProjectInit:
    VMLINUX_BTF = '/sys/kernel/btf/vmlinux'

    def __init__(
        self,
        author_name='',
        author_email='',
        project_name='',
        project_dir='.',
        project_git='',
        project_description='',
        bpf_src='bpf/prog.bpf.c',
        output_dir='.output',
    ):
        self.author_name = author_name.strip()
        self.author_email = author_email.strip()
        self.project_name = project_name.strip()
        self.project_dir = os.path.abspath(project_dir.strip())
        self.project_git = project_git.strip()
        self.project_description = project_description.strip()

        # If output_dir is not absolute, join it with our project_dir
        if not os.path.isabs(output_dir):
            self.output_dir = os.path.join(self.project_dir, output_dir)
        else:
            self.output_dir = output_dir

        # If output_dir is not absolute, join it with our project_dir
        if not os.path.isabs(bpf_src):
            self.bpf_src = os.path.join(self.project_dir, bpf_src)
        else:
            self.bpf_src = bpf_src

        self.bpf_dir = os.path.dirname(self.bpf_src)

        now = dt.datetime.now()
        self.year, self.month, self.day = now.strftime('%Y %b %d').split()

    @classmethod
    def from_toml(self, toml_path: Optional[str] = None):
        if not toml_path:
            toml_path = find_file_up_tree('pybpf.toml')
        if not toml_path:
            raise FileNotFoundError('Unable to find pybpf.toml')
        with open(toml_path, 'r') as f:
            toml_dict = toml.load(f)
        return ProjectInit(
                author_name  = toml_dict['author']['name'],
                author_email = toml_dict['author']['email'],
                project_name = toml_dict['project']['name'],
                project_dir = toml_dict['project']['root'],
                project_git = toml_dict['project']['git'],
                project_description = toml_dict['project']['description'],
                bpf_src = toml_dict['project']['bpf_src'],
                output_dir = toml_dict['project']['output_dir'],
                )

    @drop_privileges
    def to_toml(self, toml_path: Optional[str] = None):
        author_info = {
                'name': self.author_name,
                'email': self.author_email,
                }
        project_info = {
                'name': self.project_name,
                'root': self.project_dir,
                'git': self.project_git,
                'description': self.project_description,
                'bpf_src': self.bpf_src,
                'output_dir': self.output_dir,
                }
        toml_dict = {
                'author': author_info,
                'project': project_info
                }
        if toml_path is None:
            toml_path = os.path.join(self.project_dir, 'pybpf.toml')
        logger.info(f'Writing {toml_path}...')
        with open(toml_path, 'w+') as f:
            toml.dump(toml_dict, f)

    @drop_privileges
    def bootstrap_project(self, overwrite = False):
        # Make project directory
        try:
            os.makedirs(self.project_dir, exist_ok=False)
        except FileExistsError:
            if len(os.listdir(self.project_dir)) and not overwrite:
                logger.error(
                    f'{self.project_dir} is not empty! Refusing to overwrite.'
                )
                sys.exit(1)
            else:
                pass

        # Copy files over
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

        try:
            self.generate_vmlinux()
        except Exception as e:
            logger.warn(f'Unable to generate_vmlinux: {e}')

        self.to_toml()

        logger.info(f'Project bootstrapped at {self.project_dir}')

    @drop_privileges
    def generate_vmlinux(self, outdir=None) -> str:
        """
        Use bpftool to generate the vmlinux.h header file symlink for
        that corresponds with the BTF info for the current kernel.

        Creates a file "{outdir}/vmlinux_{kversion()}.h" and a symbolic link
        "{outdir}/vmlinux.h" that points to it.

        Returns the location of "{outdir}/vmlinux.h".

        Requires:
            - A recent version of bpftool in your $PATH.
            - A kernel compiled with CONFIG_DEBUG_INFO_BTF=y.
            - BTF vmlinux located at BPFObjectBuilder.VMLINUX_BTF
              ('/sys/kernel/btf/vmlinux' by default)
        """
        if outdir is None:
            outdir = self.bpf_dir

        os.makedirs(outdir, exist_ok=True)
        vmlinux_kversion_h = os.path.join(outdir, f'vmlinux_{kversion()}.h')
        vmlinux_h = os.path.join(outdir, 'vmlinux.h')

        try:
            bpftool = [which('bpftool')]
        except FileNotFoundError:
            raise OSError(
                'bpftool not found on system. '
                'You can install bpftool from linux/tools/bpf/bpftool '
                'in your kernel sources.'
            ) from None

        try:
            assert_exists(self.VMLINUX_BTF)
        except FileNotFoundError:
            raise OSError(
                f'BTF file {self.VMLINUX_BTF} does not exist. '
                'Please build your kernel with CONFIG_DEBUG_INFO_BTF=y '
                'or set ProjectInit.VMLINUX_BTF to the correct location.'
            ) from None

        bpftool_args = f'btf dump file {self.VMLINUX_BTF} format c'.split()

        with open(vmlinux_kversion_h, 'w+') as f:
            subprocess.check_call(bpftool + bpftool_args, stdout=f)

        try:
            os.unlink(vmlinux_h)
            logger.warn(f'Unlinked existing {vmlinux_h}')
        except FileNotFoundError:
            pass
        os.symlink(vmlinux_kversion_h, vmlinux_h)

        logger.info(f'Generated {vmlinux_h}')

        return vmlinux_h

    @drop_privileges
    def compile_bpf_skeleton(self, bpf_src=None, project_dir=None, cflags=[]) -> str:
        """
        Generate the BPF skeleton object for @bpf_src.
        """
        if bpf_src is None:
            bpf_src = os.path.join(self.bpf_dir, 'prog.bpf.c')
        if project_dir is None:
            project_dir = self.project_dir

        os.makedirs(self.output_dir, exist_ok=True)

        # Check for source file
        try:
            assert_exists(bpf_src)
        except FileNotFoundError:
            raise FileNotFoundError(f'Specified source file {bpf_src} does not exist.') from None

        # Check for vmlinux.h
        try:
            assert_exists(os.path.join(self.bpf_dir, 'vmlinux.h'))
        except FileNotFoundError:
            raise FileNotFoundError('Please generate vmlinux.h first with generate_vmlinux().') from None

        obj_file = os.path.join(self.output_dir, strip_full_extension(os.path.basename(bpf_src)) + '.bpf.o')

        # Check for clang
        try:
            clang = [which('clang')]
        except FileNotFoundError:
            raise FileNotFoundError('clang not found on system. '
                    'Please install clang and try again.') from None

        clang_args = cflags + f'-g -O2 -target bpf -D__TARGET_ARCH_{arch()} -I{self.output_dir}'.split() + f'-c {bpf_src} -o {obj_file}'.split()

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

        skel_h = strip_full_extension(obj_file) + '.skel.h'

        # Check for BPF tool
        try:
            bpftool = [which('bpftool')]
        except FileNotFoundError:
            raise FileNotFoundError('bpftool not found on system. '
                    'You can install bpftool from linux/tools/bpf/bpftool '
                    'in your kernel sources.') from None

        bpftool_args = f'gen skeleton {obj_file}'.split()

        # Generate skeleton header file
        logger.info(f'Generating skeleton header for BPF program {obj_file} -> {skel_h}')
        try:
            with open(skel_h, 'w+') as f:
                subprocess.check_call(bpftool + bpftool_args, stdout=f)
        except Exception as e:
            raise Exception(f'Failed to generate skeleton header: {e}') from None

        # Check for gcc
        try:
            gcc = [which('gcc')]
        except FileNotFoundError:
            raise FileNotFoundError('gcc not found on system. '
                    'Please install gcc and try again.') from None

        # Create skeleton C file
        with open(SKEL_OBJ_IN, 'r') as f:
            skel = f.read()

        skel_c = strip_full_extension(obj_file) + '.skel.c'
        skel_so = os.path.join(project_dir, os.path.basename(strip_full_extension(obj_file) + '.skel.so'))

        prefix = os.path.splitext(os.path.basename(obj_file))[0].replace('.', '_').replace('-', '_')
        skel = skel.replace('SKELETON_H', skel_h)
        skel = skel.replace('BPF', prefix)

        with open(skel_c, 'w+') as f:
            f.write(skel)

        gcc_args = cflags + f'-shared -lbpf -lelf -lz -O2 -o {skel_so} {skel_c}'.split()

        # Compile skeleton
        logger.info(f'Compiling BPF program skeleton {skel_c} -> {skel_so}')
        try:
            subprocess.check_call(gcc + gcc_args, stdout=subprocess.DEVNULL)
        except Exception as e:
            raise Exception(f'Failed to compile skeleton') from None

        logger.info(f'Compiled {skel_so} successfully')

        return skel_so
