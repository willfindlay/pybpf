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

    2020-Aug-27  William Findlay  Created this.
"""

import os
import logging

import click

from pybpf.bootstrap import Bootstrap
from pybpf.skeleton import generate_skeleton
from pybpf.cli.aliased_group import AliasedGroup

logger = logging.getLogger(__name__)


@click.group(cls=AliasedGroup)
@click.help_option('-h', '--help')
def generate():
    """
    Generate files for your pybpf project.
    """
    pass


@generate.command()
@click.argument('bpf_dir', type=click.Path(exists=True, file_okay=False, dir_okay=True), default='./bpf')
@click.help_option('-h', '--help')
def vmlinux(bpf_dir):
    """
    Generate the vmlinux.h header file and place it in BPF_DIR.
    If not specified, BPF_DIR defaults to ./bpf
    """
    bpf_dir = os.path.abspath(bpf_dir)
    try:
        Bootstrap.generate_vmlinux(bpfdir=bpf_dir)
    except Exception as e:
        logger.error(f'Unable to generate vmlinux: {repr(e)}')


@generate.command()
@click.argument(
    'bpf',
    type=click.Path(dir_okay=False, file_okay=True, exists=True),
)
@click.argument(
    'outdir',
    type=click.Path(dir_okay=True, file_okay=False, exists=True),
    default='.'
)
@click.help_option('-h', '--help')
def skeleton(outdir: str, bpf: str):
    """
    Generate the pybpf skeleton file from BPF.

    BPF is the path to the compiled BPF object file. If this file does not yet exist, run "pybpf compile" first.

    OUTDIR is the output directory for the skeleton file. If not specified, defaults to '.'
    """
    generate_skeleton(bpf, outdir)
