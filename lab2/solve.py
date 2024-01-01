import pow as pw
from pwn import *
import base64

r = remote('up23.zoolab.org', 10363)
pw.solve_pow(r)


text = r.recvuntil(" challenges").decode()

num = text.split(" challenges")[0].split(" ")[-1]

print("Challenge number is ", int(num))

for i in range(int(num)):
    eq_text = r.recv().decode()
    print(eq_text)
    eq = eq_text.split(":")[1].split(" = ")[0]

    print("========")
    print("eq is ", eq)

    res = eval(eq)
    print("result is ", res)
    print("========")

    r.sendline(base64.b64encode(res.to_bytes((res.bit_length() + 7) // 8, 'little')))
    

final = r.recv().decode()
final = r.recv().decode()
print(final)

r.close()