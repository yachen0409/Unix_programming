#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break;
    print(time.time(), "done.")

    r.sendlineafter(b'string S: ', base64.b64encode(solved))
def solve_num(r):
    nouser = r.recv()
    what_i_want = r.recv().decode()
    test = (int)(what_i_want.split(" ")[7])
    print(test)
    for i in range(test):
    
        prefix = what_i_want.split(":")[1]
        cal = prefix.split("=")[0]
        num1 = (int)(cal.split(" ")[1])
        num2 = (int)(cal.split(" ")[3])
        operation = cal.split(" ")[2]
        result = 0
        if operation == "+":
            result = num1+num2
        elif operation == "-":
            result = num1-num2
        elif operation == "*":
            result = num1*num2
        elif operation == "/":
            result = num1 / num2
        elif operation == "%":
            result = num1%num2
        elif operation == "**":
            result = num1**num2
        elif operation == "//":
            result = num1//num2

        byte_string = result.to_bytes((result.bit_length() + 7) // 8, 'little')

        # Encode the byte string using Base64
        encoded_bytes = base64.b64encode(byte_string)

        # Convert the encoded bytes to a little-endian binary string
        print(encoded_bytes)
        r.sendline(what_i_want, encoded_bytes)
        what_i_want = r.recv().decode()
        
    result = r.recv().decode()
    print(result)

if __name__ == '__main__':
    #r = remote('localhost', 10330);
    r = remote('up23.zoolab.org', 10363)
    solve_pow(r)
    #r.interactive()
    solve_num(r)
    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
