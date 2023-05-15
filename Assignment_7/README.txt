Ubuntu 20.04.5 LTS
GNU bash, version 5.0.17(1)-release (x86_64-pc-linux-gnu)
gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0


The program has been compiled for my OS.

Firstly, we observe the mprotect() function called in main which sets the
big_boy_buffer as executable. big_boy_buffer is where we will put our shellcode.

In function vuln(), gets() function writes in buffer the input. Then, with
memcpy(), buffer is copied into big_boy_buffer. Because memcpy copies 100
characters in this program, our shellcode must not be longer than that.

A shellcode is found from https://shell-storm.org/shellcode/files/shellcode-104.html

After experimenting with inputs, it has been found that after 120 characters we
start to overwrite the rip saved in the stack. How: In gdb, right after the
execution of gets(), we can see the rip saved in the stack (which is the next
command after the ret) with the command `i f` (info frame); after a normal
execution its output is:

	Stack level 0, frame at 0x7fffffffe380:
	 rip = 0x401283 in vuln (pwn.c:45); saved rip = 0x401406
	 called by frame at 0x7fffffffe3a0
	 source language c.
	 Arglist at 0x7fffffffe2f8, args:
	 Locals at 0x7fffffffe2f8, Previous frame's sp is 0x7fffffffe380
	 Saved registers:
	  rbp at 0x7fffffffe370, rip at 0x7fffffffe378

So, in normal execution the saved rip has the value 0x401406. We experiment with
inputs and observe this value and we find that we need 120 characters until we
overwrite the saved rip.

The address of big_boy_buffer has been found from gdb and this will be the value
that we will overwrite the saved rip in the stack. How: Using the command `x
big_boy_buffer` the output is

	0x404080 <big_boy_buffer>:      0x00000000

so the address 0x404080 is the address that we want to go after the function
vuln() returns since there will be our shellcode that we want to execute. The
way to achieve this is by overwriting the saved rip mentioned above with the
address of big_boy_buffer 0x404080. We must be carefull with the little-endian.

So, finally, our payload will be the shellcode (and after it a '\0' to terminate
the string "/bin/sh" which is the final thing in the shellcode), an appropriate
amount of dummy characters in order to reach the rip saved in the stack, i.e.
120-len(shellcode+'\0'), and then the desired address for the saved rip which is
the big_boy_buffer. We add and a '\n' character at the end of the payload so as
gets() stops here.

Create payload.bin using the bash command `./create_payload.py > payload.bin`.

After that, we must redirect the input to stdin since the shell will have opened
and we want to write commands. So, to exploit the program we run from bash `(cat
payload.bin ; cat) | ./bof`.

