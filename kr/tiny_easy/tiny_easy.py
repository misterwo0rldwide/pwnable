from pwn import *

s = ssh(user='tiny_easy', host='pwnable.kr', port=2222, password='guest')
p = s.process('/home/tiny_easy/tiny_easy')
p.interactive()
