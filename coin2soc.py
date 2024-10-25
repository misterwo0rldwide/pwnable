import socket
import time
client = socket.socket()
client.connect(("0", 9008))
print(client.recv(10000).decode())
time.sleep(3)

for i in range(100):
    d = client.recv(2048).decode()
    N,C = int(d.split()[0].split("=")[-1]), int(d.split()[1].split("=")[-1])
    #need to do Hamming style algorithem in order to find the counterfit coin
    checks = []
    for i in range(C):
        t = []
        for j in range(N):
            if (j>>i)%2==1:
                t.append(j)
        checks.append(t)
    payload = ("-".join([" ".join(map(str,check)) for check in checks])).encode() + b"\n"
    client.send(payload)
    d = client.recv(2048).decode()
    d = d.split('-')
    d  = [int(num) for num in d]
    res = 0
    for i in range(C):
        if d[i]%10==9:
            res += 2**i
    client.send(str(res).encode() + b"\n")
    print(client.recv(2048).decode())
    
    

print(client.recv(2048).decode())