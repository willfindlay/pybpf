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

from pybpf.project_init import ProjectInit
from pybpf.cli.aliased_group import AliasedGroup

logger = logging.getLogger(__name__)

@click.command(help='Build the BPF skeleton object.')
@click.help_option('-h', '--help')
def build():
    project_dir = os.path.abspath('.')

    proj_init = ProjectInit(project_dir=project_dir)
    try:
        proj_init.compile_bpf_skeleton()
    except Exception as e:
        logger.error(f'Unable to compile BPF skeleton: {e}')

