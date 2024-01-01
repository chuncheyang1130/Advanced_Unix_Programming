from pwn import *

context.arch = 'amd64'

print(asm("""pop rax
ret"""))

print(asm("""pop rdi
ret"""))

print(asm("""pop rsi
ret"""))

print(asm("""pop rdx
ret"""))

print(asm("""syscall
ret"""))