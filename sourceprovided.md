
# source provided
DownUnder CTF 2022; Rev (Beginner)

Writeup by danlliu from WolvSec (solved)

## General Approach

We are given an assembly file, which contains a array of bytes and a loop that performs operations on the input and compares it to the array of bytes. We need to find the flag, which, when input into the assembly file, will lead to the program exiting with a `0` status code.

## Solution

The assembly file is shown below:

```as
SECTION .data
c db 0xc4, 0xda, 0xc5, 0xdb, 0xce, 0x80, 0xf8, 0x3e, 0x82, 0xe8, 0xf7, 0x82, 0xef, 0xc0, 0xf3, 0x86, 0x89, 0xf0, 0xc7, 0xf9, 0xf7, 0x92, 0xca, 0x8c, 0xfb, 0xfc, 0xff, 0x89, 0xff, 0x93, 0xd1, 0xd7, 0x84, 0x80, 0x87, 0x9a, 0x9b, 0xd8, 0x97, 0x89, 0x94, 0xa6, 0x89, 0x9d, 0xdd, 0x94, 0x9a, 0xa7, 0xf3, 0xb2

SECTION .text

global main

main:
    xor rax, rax
    xor rdi, rdi
    mov rdx, 0x32
    sub rsp, 0x32
    mov rsp, rsi
    syscall

    mov r10, 0
l:
    movzx r11, byte [rsp + r10]
    movzx r12, byte [c + r10]
    add r11, r10
    add r11, 0x42
    xor r11, 0x42
    and r11, 0xff
    cmp r11, r12
    jne b

    add r10, 1
    cmp r10, 0x32
    jne l

    mov rax, 0x3c
    mov rdi, 0
    syscall

b:
    mov rax, 0x3c
    mov rdi, 1
    syscall
```

Looking at the assembly, we have a data section with an array of bytes. Additionally, we have a loop that runs for every element in the input. Based on a quick look at the assembly, the flag is likely passed in as a parameter, which would exist at the address pointed to by `rsp` (the stack pointer). Let's take a closer look at the loop:

```as
l:
    movzx r11, byte [rsp + r10]
    movzx r12, byte [c + r10]
    add r11, r10
    add r11, 0x42
    xor r11, 0x42
    and r11, 0xff
    cmp r11, r12
    jne b

    add r10, 1
    cmp r10, 0x32
    jne l
```

Since `r10` starts at 0 and increases to 32, it is our index into the flag and the `c` array. Thus, we'll refer to `r10` as our index `i`. The operations performed here are:

```python
r11 = flag[i]
r12 = c[i]

r11 += i
r11 += 0x42
r11 = r11 ^ 0x42
r11 = r11 & 0xff
if r11 != r12:
  sys.exit(1)
i += 1
if i == 0x32:
  sys.exit(0)
else:
  # continue the loop
```

where `^` is bitwise XOR and `&` is bitwise AND. Thus, we can work our way backwards from each value of `c`. Let's take the first value, `0xc4`, as an example. We'll give each of our intermediate `r11` values a different name for clarity:

```
r12 = 0xc4

r11_0 = flag[i]
r11_1 = r11_0 + i
r11_2 = r11_1 + 0x42
r11_3 = r11_2 ^ 0x42
r11_4 = r11_3 & 0xff
r11_4 == r_12
```

We know that `r11_4` is equal to `r12`, and thus `r11_4 = 0xc4`. 

Next, let's find the value of `r11_3`. We _technically_ don't know what `r11_3` is, but since the flag is all ASCII values, we can start by assuming `r11_3` is equal to `r11_4`, and offset it by 256 later if necessary (remember that `& 0xff` is equivalent to `% 256`). 

Next, we know that `r11_2` is equal to `r11_3 ^ 0x42`, since `r11_3 = r11_2 ^ 0x42`, and XOR is its own inverse. Thus, `r11_2` = `0x86`.

To find the value of `r11_1`, we know that `r11_2 = r11_1 + 0x42`. Thus, `r11_1 = r11_2 - 0x42 = 0x44`.

Finally, to find the value of `r11_0`, we use the current index, which is 0. We thus find that `r11_0 = r11_1 - i = 0x44 - 0 = 0x44 = 'D'`

We can automate this process using the Python code below. Note that if `r11_1` ends up negative, we can add `256` to it without having to recalculate everything, because the higher order bits are not affected and eventually are masked off when computing `r11_4`.

```python
data = [0xc4, 0xda, 0xc5, 0xdb, 0xce, 0x80, 0xf8, 0x3e, 0x82, 0xe8, 0xf7, 0x82, 0xef, 0xc0, 0xf3, 0x86, 0x89, 0xf0, 0xc7, 0xf9, 0xf7, 0x92, 0xca, 0x8c, 0xfb, 0xfc, 0xff, 0x89, 0xff, 0x93, 0xd1, 0xd7, 0x84, 0x80, 0x87, 0x9a, 0x9b, 0xd8, 0x97, 0x89, 0x94, 0xa6, 0x89, 0x9d, 0xdd, 0x94, 0x9a, 0xa7, 0xf3, 0xb2]

for i, v in enumerate(data):
    r11_4 = v
    r11_3 = r11_4
    r11_2 = r11_3 ^ 0x42
    r11_1 = r11_2 - 0x42
    if r11_1 < 0:
        r11_1 += 256
    r11_0 = r11_1 - i
    print(chr(r11_0), end='')

print()  # have a newline at end of output
```

Running this script gives us our flag!

Solution: `DUCTF{r3v_is_3asy_1f_y0u_can_r34d_ass3mbly_r1ght?}`
