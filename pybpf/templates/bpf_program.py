#! /usr/bin/env python3

"""
    PROJECT_NAME
    Copyright (C) YEAR AUTHOR_NAME <AUTHOR_EMAIL>

    PROJECT_DESCRIPTION

    <LICENSE HERE>

    YEAR-MONTH-DAY  AUTHOR_NAME  Created this.
"""

import os
import time

from pybpf import BPFObject, ProjectInit

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
BPF_DIR  = os.path.join(PROJECT_DIR, 'bpf')
BPF_SRC  = os.path.join(BPF_DIR, 'prog.bpf.c')
SKEL_OBJ = os.path.join(PROJECT_DIR, 'prog.skel.so')

TICKSLEEP = 0.1

def main():

    # For development:
    init = ProjectInit.from_toml()
    init.compile_bpf_skeleton(BPF_SRC)
    bpf = BPFObject(SKEL_OBJ, True, True)

    # TODO: For production:
    # bpf = BPFObject(SKEL_OBJ, True, True)

    # TODO: Add your program logic here

    while 1:
        time.sleep(0.1)

if __name__ == '__main__':
    main()
