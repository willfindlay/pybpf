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

from __future__ import annotations
import os
import readline
import logging
from typing import Optional

import click

# This is better than nothing. Fixes a readline issue where user can overwrite
# the prompt. https://github.com/pallets/click/issues/665
click.termui.visible_prompt_func = lambda x: input(" ")

from pybpf.cli.aliased_group import AliasedGroup
from pybpf.cli.pybpf_init import init
from pybpf.cli.pybpf_gen import generate
from pybpf.cli.pybpf_compile import build

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

@click.group(help='Manage pybpf projects', cls=AliasedGroup)
@click.option('--debug', flag_value=True, default=False, hidden=True)
@click.help_option('-h', '--help')
def pybpf(debug=False):
    """
    Main pybpf program.
    """
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)


def main():
    pybpf.add_command(init)
    pybpf.add_command(generate)
    pybpf.add_command(build)
    pybpf()
