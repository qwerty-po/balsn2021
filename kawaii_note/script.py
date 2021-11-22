import gdb
import string

gdb.execute("file kawaii_note")
gdb.execute('b printf')
while(1):
#for i in range(1):
    gdb.execute('r')
    result = gdb.execute("vmmap", to_string = True)
    result1 = result.split("/home/qwerty/ctf/balsn2021/kawaii_note/kawaii_note")
    result2 = result.split("/usr/lib/x86_64-linux-gnu/libm-2.31.so")
    if(bytes(result1[5].split(" ")[0].encode('utf-8')).replace(b'\x1b[0m', b'').replace(b'\n\x1b[32m', b'')[-4:-2] != b'c0'):
        continue
    if(bytes(result2[5].split(" ")[0].encode('utf-8').replace(b'\x1b[0m', b'')).replace(b'\n', b'')[-4:-2] != b'50'):
        continue
    else:
        break

