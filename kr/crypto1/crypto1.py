# When solving this challenge what we will do is discover cookie values
# This can be done because AES is a block cipher, so by discovering byte by byte
# From left to right we can know the content of cookie

# The way of solving it -
# lets say our buffer before encrypting is
# --------------- + cookie (id = "-" * 13 and pw = "")
# then we can do know that because it is 128 bit block cipher
# we know that the first letter of cookie is the last byte in the first block (since we have 15 '-').
# Now we will test different last bytes to see if it equals to the first block encrypted before
# AES128_CBC(---------------a) == AES128_CBC(--------------- + cookie[0]) ?

# Then continue on each time
# Lets say we discovered first byte of cookie is 'p', then
# AES128_CBC(--------------b<test_byte>) == AES128_CBC(-------------- + cookie[:2]) ?

# Now after we discover the first 14 bytes we still have 16 bytes left to discover (30 bytes total)
# We will do the same for those 16 bytes but we will perform it on the second block (so its important to not change the first block while testing this)

# After all of cookie values were discovered we would just calculate
# hashlib.sha256('admin'+cookie).hexdigest() which would be pw

# BOOM CHAKALKA
from pwn import *
import hashlib

first_encrypted_data_byte = b"("
last_encrypted_data_byte = b")"

cookie = b""

# Run inside pwnable.kr server
def send_id_pw(id, pw):
    r = remote("localhost", 9006)

    r.sendline(id)
    r.sendline(pw)

    data = r.recvuntil(last_encrypted_data_byte).split(first_encrypted_data_byte)[-1][:-1]

    r.close()
    return data

# Discover first 14 bytes
for i in range(14, 0, -1):
    id = b"-" * (i - 1)
    pw = b""

    encrypted_data = send_id_pw(id, pw)
    first_block = encrypted_data[:32]

    for c in "1234567890abcdefghijklmnopqrstuvwxyz-_":
        id = b"-" * (i + 1) + cookie + c.encode()
        print("Trying: ", id)

        encrypted_try = send_id_pw(id, pw)
        first_block_try = encrypted_try[:32]

        if first_block == first_block_try:
            cookie += c.encode()
            print("Found byte, cookie is now -", cookie)

            break

# After this we find out first 14 bytes are cookie = "t0p_s3cret_s3r"
# now we will focus on the other 16 bytes

for i in range(16, 1, -1):
    id = b"-" * (i - 1)
    pw = b""

    encrypted_data = send_id_pw(id, pw)
    second_block = encrypted_data[32:64]
    print("Second block is:", second_block)

    for c in "1234567890abcdefghijklmnopqrstuvwxyz-_":
        id = b"-" * (i + 1) + cookie + c.encode()
        print("Trying: ", id)

        encrypted_try = send_id_pw(id, pw)
        second_block_try = encrypted_try[32:64]

        if second_block_try == second_block:
            cookie += c.encode()
            print("Found byte, cookie is now -", cookie)

            break

r = remote("localhost", 9006)

id = b"admin"
pw = hashlib.sha256(id + cookie).hexdigest().encode()

r.sendline(id)
r.sendline(pw)

r.recvuntil(b"flag")
flag = r.recv()[1:-2].decode()
print("Flag is:", flag)

r.close()