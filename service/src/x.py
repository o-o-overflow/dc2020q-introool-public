#!/usr/bin/env python3

import os
from os.path import *
import sys
import traceback
import binascii
import base64
import tempfile

import click


MIN_NOPSLED_SIZE = 0x80
MAX_NOPSLED_SIZE = 0x800
TEMPLATE_FP = 'c.template'
LDS_FP = 'script.lds'

gdebug = False
gtest = False


@click.group()
def cli():
    pass


@cli.command()
@click.option('--dir', 'working_dir', default=None)
@click.option('-d', '--debug', is_flag=True)
@click.option('-t', '--test', is_flag=True)
def doit(working_dir, debug, test):
    global gdebug, gtest
    gdebug = debug
    gtest = test

    if working_dir is None:
        working_dir = dirname(__file__)
    working_dir = abspath(working_dir)

    try:
        if gdebug:
            out(f'Working dir: {working_dir}\n')
    
        if not isdir(working_dir):
            err('ERROR: contact admins')

        if not gtest:
            nopsled_byte_str = input('Insert NOP 🛷 byte in hex (e.g., "90"). The byte must be >= 0x80.\n> ')
        else:
            nopsled_byte_str = '90'
        assert len(nopsled_byte_str) == 2
        nopsled_byte = bytearray.fromhex(nopsled_byte_str)[0]
        if nopsled_byte & 0x80 == 0:
            out('WARNING: 🛷 byte too low for our standards. Bumping it up!\n')
            nopsled_byte |= 0x80

        if not gtest:
            nopsled_size = int(input(f'Insert size of 🛷 in hex (e.g., "200"). Valid range is [{hex(MIN_NOPSLED_SIZE)}, {hex(MAX_NOPSLED_SIZE)}].\n> '), 16)
        else:
            nopsled_size = 300
        assert MIN_NOPSLED_SIZE <= nopsled_size <= MAX_NOPSLED_SIZE
        if nopsled_size % 4 != 0:
            nopsled_size += (4 - (nopsled_size % 4))
        assert nopsled_size % 4 == 0

        nopsled = bytearray([nopsled_byte]) * nopsled_size

        p1_off, p1_val = ask_patch('🛠️\n', nopsled_size)
        p2_off, p2_val = ask_patch('⛏️\n', nopsled_size)
        out('👌\n')

        nopsled[p1_off] = p1_val
        nopsled[p2_off] = p2_val

        out('Insert your three ROP ⛓️  gadgets in hex (e.g., "baaaaaadc0000ffe").\n')
        ropchain = bytes()
        for idx in range(3):
            if not gtest:
                rs = ask(f'[{idx+1}/3] > ')
            else:
                rs = 'baaaaaadc0000ffe'
            assert len(rs) == 16
            r = bytes.fromhex(rs)
            ropchain += r
        assert len(ropchain) == 24

        introll_fp = gen_elf(nopsled, ropchain, working_dir)

        out('Now what?\n')
        out('1. 🔬\n')
        out('2. 💥\n')
        ans = int(ask('> '))
        if ans == 1:
            with open(introll_fp, 'rb') as f:
                content = f.read()
            out(base64.b64encode(content).decode('utf-8') + '\n')
        elif ans == 2:
            run(f'timeout -k1 5 stdbuf -i0 -o0 -e0 {introll_fp}')
        else:
            err('🚫\n')

    except Exception as e:
        if debug:
            out(traceback.format_exc())
        err('🚫\n')


def gen_elf(nopsled, ropchain, working_dir):
    introll_template_fp = join(dirname(__file__), TEMPLATE_FP)
    with open(introll_template_fp, 'rb') as f:
        template = f.read()

    asmcode = gen_asm(nopsled)
    data = b'A' * len(ropchain)
    introll = template.replace(b'<asmcode>', asmcode)
    introll = introll.replace(b'<data>', data)

    introll_c_fp = join(working_dir, 'introll.gen.c')
    introll_o_fp = join(working_dir, 'introll.gen.o')
    introll_lds_fp = join(dirname(__file__), LDS_FP)
    introll_fp = join(working_dir, 'introll.gen')

    with open(introll_c_fp, 'wb') as f:
        f.write(introll)

    run(f'gcc -c -o {introll_o_fp} {introll_c_fp}')
    assert isfile(introll_o_fp)
    run(f'ld -o {introll_fp} -T {introll_lds_fp} {introll_o_fp}')
    assert isfile(introll_fp)

    with open(introll_fp, 'rb') as f:
        content = f.read()

    idx = content.find(data)
    assert idx >= 0
    # check that the placeholder doesn't show up twice for some reason
    assert content.find(data, idx+1) == -1

    content = content.replace(data, ropchain)

    with open(introll_fp, 'wb') as f:
        f.write(content)

    return introll_fp


def run(cmd):
    if gdebug:
        out(f'CMD: {cmd}')
    os.system(cmd)


def gen_asm(nopsled):
    assert len(nopsled) % 4 == 0

    out = ''
    for idx in range(int(len(nopsled)/4)):
        out += '__asm__(".4byte 0x%s");\n' % binascii.hexlify(nopsled[4*idx:4*(idx+1)][::-1]).decode('ascii')
    return out.encode('ascii')


def ask_patch(msg, nopsled_size):
    out(msg)
    if not gtest:
        off = int(input('Insert offset to patch in hex (e.g., "909"): '), 16)
    else:
        off = 0
    assert 0 <= off < nopsled_size
    if not gtest:
        val = int(input('Insert value to patch with in hex (e.g., "90"): '), 16)
    else:
        val = 0x90
    assert 0 <= val < 256
    return off, val


def ask(msg):
    out(msg)
    return input()

def out(msg):
    sys.stdout.write(msg)
    sys.stdout.flush()

def err(msg):
    out(msg)
    sys.exit(1)


if __name__ == '__main__':
    cli()
