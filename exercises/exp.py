#!/usr/bin/env python2
# -*- coding: utf-8 -*
import re
import os
from pwn import *


se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb, timeout = 1)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
lg = lambda name,data : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)

def debug(breakpoint=''):
    glibc_dir = '~/Exps/Glibc/glibc-2.27/'
    gdbscript = 'directory %smalloc/\n' % glibc_dir
    gdbscript += 'directory %sstdio-common/\n' % glibc_dir
    gdbscript += 'directory %sstdlib/\n' % glibc_dir
    gdbscript += 'directory %slibio/\n' % glibc_dir
    gdbscript += 'directory %self/\n' % glibc_dir
    gdbscript += 'set follow-fork-mode parent\n'
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p, gdbscript)
    time.sleep(1)

elf = ELF("./MercuryBlast")
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])

# def add_record(temp, size, data):
#     sla("Your choice: ", "1")
#     sla("Input Temperature:", str(temp))
#     sla("Input Description Size: ", str(size))
#     sa("Input Description: ", data)

# def print_record():
#     sla("Your choice: ", "2")
#     # sla("Input Index:", str(idx))

# def delete_record(idx):
#     sla("Your choice: ", "3")
#     sla("Input Index:", str(idx))

# def edit_record(idx, temp, size, data):
#     sla("Your choice: ", "4")
#     sla("Input index: ", str(idx))
#     sla("Input Temperature:", str(temp))
#     sla("Input Description Size: ", str(size))
#     sa("Input Description: ", data)

# def blast(data):
#     sla("Your choice: ", str('\x7f'))
#     se(data)


p = process(["./heap_experiment", 1])
debug()
