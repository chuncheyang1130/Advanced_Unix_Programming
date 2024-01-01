from pwn import asm, elf


e = elf.from_assembly(machine_code)
e.save('new_solver')