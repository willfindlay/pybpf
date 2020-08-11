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

    2020-Aug-11  William Findlay  Created this.
"""

from __future__ import annotations
import os
import readline
import logging
from urllib.parse import urlparse
from email.utils import parseaddr as emailparse
from typing import Optional

import click

# This is better than nothing. Fixes a readline issue where user can overwrite
# the prompt. https://github.com/pallets/click/issues/665
click.termui.visible_prompt_func = lambda x: input(" ")

from pybpf.project_init import ProjectInit

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

logger = logging.getLogger(__name__)

class URL(click.ParamType):
    name = 'url'

    def is_valid(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc, result.path])
        except Exception:
            return False

    def convert(self, value, param, ctx):
        if not (self.is_valid(value)):
            self.fail(f'Invalid URL {value}')
        return value


class Email(click.ParamType):
    name = 'email'

    def convert(self, value, param, ctx):
        try:
            name, email = emailparse(value)
        except Exception:
            name, email = ('', '')
        if not email:
            self.fail(f'Invalid email {value}')
        if not '@' in email:
            self.fail('Email should contain an "@" symbol')
        return email


def continually_prompt():
    yield True
    while True:
        if click.confirm(
            click.style('Is this correct?', fg='yellow'), default=True
        ):
            print()
            return
        yield True


@click.group(help='Manage pybpf projects')
@click.help_option('-h', '--help')
def pybpf():
    """
    Main pybpf program.
    """
    pass


@pybpf.command(help='Create a pybpf project')
@click.option(
    '--name',
    'author_name',
    type=str,
    default=None,
    help='Name of the project author',
)
@click.option(
    '--email',
    'author_email',
    type=Email(),
    default=None,
    help='Email of the project author',
)
@click.option(
    '--git',
    'project_git',
    type=URL(),
    default=None,
    help='URL for the project git upstream',
)
@click.option(
    '--dir',
    'project_dir',
    type=click.Path(file_okay=False, dir_okay=True),
    default=None,
    help='Directory to create for the project',
)
@click.option(
    '--description',
    'project_description',
    type=str,
    default=None,
    help='A one line description of the project',
)
@click.option(
    '--overwrite',
    is_flag=True,
    default=False,
    help='Overwrite the target directory if it exists',
        )
@click.help_option('-h', '--help')
def init(author_name, author_email, project_git, project_dir, project_description, overwrite):
    """
    Initialize a pybpf project.
    """
    # Get author name
    if author_name is None:
        for _ in continually_prompt():
            author_name = click.prompt('Author name')

    # Get author email
    if author_email is None:
        for _ in continually_prompt():
            author_email = click.prompt(
                'Author email (empty skips)', type=Email(), default=''
            )

    # Get project directory and project name
    if project_dir is None:
        for _ in continually_prompt():
            project_dir = click.prompt(
                'Project directory',
                type=click.Path(file_okay=False, dir_okay=True),
            )

    project_dir = os.path.abspath(project_dir)
    project_name = os.path.basename(project_dir)

    # Get project git
    if project_git is None:
        for _ in continually_prompt():
            project_git = click.prompt(
                'Project git (empty skips)', type=URL(), default=''
            )

    # Get a project description
    if project_description is None:
        project_description = ''
        for _ in continually_prompt():
            project_description = click.prompt(
                'Project description (empty skips)', type=str, default=''
            )

    proj_init = ProjectInit(
        author_name,
        author_email,
        project_name,
        project_dir,
        project_git,
        project_description,
    )
    proj_init.bootstrap_project(overwrite=overwrite)


@pybpf.command(help='Generate vmlinux.h')
@click.help_option('-h', '--help')
def vmlinux():
    project_dir = os.path.abspath('.')

    proj_init = ProjectInit(project_dir=project_dir)
    try:
        proj_init.generate_vmlinux()
    except Exception as e:
        logger.error(f'Unable to generate vmlinux: {e}')


@pybpf.command(help='Compile the BPF skeleton object')
@click.help_option('-h', '--help')
def compile():
    project_dir = os.path.abspath('.')

    proj_init = ProjectInit(project_dir=project_dir)
    try:
        proj_init.compile_bpf_skeleton()
    except Exception as e:
        logger.error(f'Unable to compile BPF skeleton: {e}')


def main():
    pybpf()
