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

from pybpf import Bootstrap

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
BPF_DIR  = os.path.join(PROJECT_DIR, 'bpf')
BPF_SRC  = os.path.join(BPF_DIR, 'prog.bpf.c')

# For development only:
Bootstrap.bootstrap(BPF_SRC)

from prog_skel import ProgSkeleton

TICKSLEEP = 0.1

def main():

    skel = ProgSkeleton()

    # TODO: Your code here

    while 1:
        time.sleep(0.1)

if __name__ == '__main__':
    main()
