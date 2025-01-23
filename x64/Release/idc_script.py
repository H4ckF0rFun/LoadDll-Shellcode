from pwn import * 

start = 0x00140001000
end = 0x01400015CF

entry = 0x001400015A0

data = idc.get_bytes(start,end - start)
jmp = b'\xe9' + p32(entry - start)

sc = b''
sc += jmp
sc += data
sc += p32(0)
sc += b'\x00' * 0x10
sc += b'\x00' * 0x100


with open("loaddll_sc","wb") as f:
    f.write(sc)