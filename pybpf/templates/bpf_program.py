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

from pybpf import BPFObjectBuilder

BPF_DIR  = os.path.join(os.path.dirname(__file__), 'bpf')
BPF_SRC  = os.path.join(BPF_DIR, 'prog.bpf.c')
SKEL_OBJ = os.path.join(BPF_DIR, '.output/prog.skel.so')

TICKSLEEP = 0.1

def main():
    builder = BPFObjectBuilder()

    # For development:
    builder.generate_skeleton(BPF_SRC)

    # TODO: For production:
    # try:
    #     builder.use_existing_skeleton(SKEL_OBJ)
    # except FileNotFoundError:
    #     builder.generate_skeleton(BPF_SRC)

    bpf = builder.build()

    # TODO: Add your program logic here

    while 1:
        time.sleep(0.1)

if __name__ == '__main__':
    main()
