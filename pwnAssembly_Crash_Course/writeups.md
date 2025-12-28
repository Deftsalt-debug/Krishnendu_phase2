# 1. Set register
We utilise the mov command here, straightforward. Setting rdi = 0x1337.

```asm
mov rdi, 0x1337
```

Then on terminal, we assemble the asm to binary
```bash
nasm -f bin solve.asm -o shellcode.bin
```

and then pass it to the chal
```bash
cat shellcode.bin | /challenge/run
```

This is the exact procedure we use throughout this module. 

## Flag
`pwn.college{Y1hB_Ce9xwDAezWWDTzYlk2eStz.dRTOxwiMwkjNzEzW}`


***

# 2. Set multiple registers
Here, we're asked to set multiple registers. 

```asm
mov rax, 0x1337
mov r12, 0xCAFED00D1337BEEF
mov rsp, 0x31337
```

## Flag
`pwn.college{8Jn6WUH5YCTObLDAQ7get47NBWd.QXwEDOzwiMwkjNzEzW}`


***

# 3. Add to register
Here, we utilise the add command to perform basic arithmetic on registers. 

```asm
add rdi, 0x331337
```

## Flag
`pwn.college{QLrDGCN_9RQqAz1ljViRNvoge5V.dVTOxwiMwkjNzEzW}`


***

# 4. Linear Equation Registers
This challenge utilised the use of imul (signed multiplication) to perform a linear equation. f(x) = mx + b, where m is rdi, x is rsi and b is rdx.

```asm
imul rdi, rsi
mov rax, rdi
add rax, rdx
```

## Flag
`pwn.college{w_Pt2kEkEVISy5vYNmQ8RPArOmI.dZTOxwiMwkjNzEzW}`

***

# 5. Integer divison
We further carry on computing using the div function to perform integer division. We use the simple speed equation via asm.

```asm
mov rax, rdi    
div rsi 
```

## Flag
`pwn.college{sW6FgtXisIMGx35ERuT2WKA0UKV.ddTOxwiMwkjNzEzW}`


***

# 6. Modulo operation 
Here we're to compute rdi % rsi via the div function but utilising the remainder register.

```asm
mov rax, rdi
div rsi
mov rax, rdx
```

## Flag
`pwn.college{M9oB1aXPBjz0ow_Pbh5-vVkDpCP.dhTOxwiMwkjNzEzW}`

***

# 7. Set Upper Byte
Here we learn about parital registers and how they can be used to set specific bytes under an entire qword. We're to set the upper 8 bits of the ax register to 0x42.

```asm
mov ah, 0x42
```

## Flag
`pwn.college{sx-6bodBizXFr-VfcVnLQTThYlq.QXxEDOzwiMwkjNzEzW}`


***

# 8. Efficient modulo
I was stuck on this level for quite a bit, the powers of two were quite confusing to me so this took extra time and research. We're to compute rax = rdi % 256 and rbx = rsi % 65536. The concept applied is the fact that on the case of x % y, and y is a power of 2, such as 2^n, the result will be the lower n bits of x. 

```asm
mov rax, 0
mov al, dil

mov rbx, 0
mov bx, si
```

## Flag
`pwn.college{Af28nHqecAE3rxgCfSS8cy1kT1Y.dlTOxwiMwkjNzEzW}`

***

# 9. Byte Extraction
We use bit shifting to perform exraction of a speficic byte under a register. Here we're to extract the 5th LSB of rdi.

```asm
mov rax, rdi
shr rax, 32
shl rax, 56
shr rax, 56
```

Here the shift by 56 cleans up the rest of the bytes except the one we want to extract. 

## Flag
`pwn.college{EysKolU7A1GFJoNUPYYm5Fymhiu.dBDMywiMwkjNzEzW}`

***

# 10. Bitwise AND
Here we learn about using bitwise operations in asm, specifically AND, viewing truth tables and how we can perform those on registers itself.

```asm
and rdi, rsi
and rax, rdi
```

## Flag
`pwn.college{gQdCpfgi7OlPLIbf9tD74mVqZ-q.dFDMywiMwkjNzEzW}`

***

# 11. Check Even
We have to perform a logical statement to check in the register is even and set the other to a value in accordance to the condition.

```asm
or  rax, rdi     
and rax, 1        
xor rax, 1        
```

Here the or performs as a mov in disguise as rax is entirely 0. 

## Flag
`pwn.college{IvHAveNkJuTkiMXO92WCzo7Evji.dJDMywiMwkjNzEzW}`

***

# 12. Memory read 
Here the learn the syntax of memory and addresses in asm, utilising the [] brackets to specify data or an actual address. We're to place the value stored at 0x404000 into rax. 

```asm
mov rax, [0x404000]
```

## Flag
`pwn.college{Qr5ekHa88OWY1U_h3TPHbD9Hm1P.QXyEDOzwiMwkjNzEzW}`

***

# 13. Memory write
This is iterative off of the previous challenge, we're to place the value stored in rax to 0x404000.

```asm
mov [0x404000], rax
```

## Flag
`pwn.college{ABc-ddENdl4_RUqnpEIFu3t0q5N.QXzEDOzwiMwkjNzEzW}`

***

# 14. Memory increment
Given is a read, modify, write set of instructions we need to perform on the memory. We're to increment the value stored in the address 0x404000 by 0x1337

```asm
mov rax, [0x404000]    
mov rbx, rax           
add rbx, 0x1337        
mov [0x404000], rbx    
```

## Flag
`pwn.college{Ik9YNMobSEiv-QfDnSb9Kd0Cq35.dNDMywiMwkjNzEzW}`

***

# 15. Byte access. 
Here, we learn about qwords, dwords and moreon, this is to further amplify the understanding of partial registers. Through these, we can access each of these sizes when dereferencing an address or a register. We're to set rax to the byte at 0x404000.

```asm
mov al, [0x404000]
```

## Flag
`pwn.college{4sx3HlGAy7bpMvsC4_4q08sVyQE.QX0EDOzwiMwkjNzEzW}`

***

# 16. Memory size access
We're to set multiple registers to various sizes. 

```asm
mov al,  byte [0x404000]
mov bx,  word [0x404000]
mov ecx, dword [0x404000]
mov rdx, qword [0x404000]
```

## Flag
`pwn.college{MpA9mFAdWz6I-o0anl2p7ZNk85G.dRDMywiMwkjNzEzW}`

***

# 17. Little Endian Write
Here, we learn about little endian and it's format of storing in memory in a reverse order. We're to set [rdi] = 0xdeadbeef00001337 as well as [rsi] = 0xc0ffee0000
 
```asm
mov rax, 0xdeadbeef00001337
mov [rdi], rax

mov rax, 0xc0ffee0000
mov [rsi], rax
```

This requires a little nuance as x86 encoding rules do not allow a 64-bit immediate to be written directly to memory. Therefore large intermediates must live in registers first before being moved about. 

## Flag
`pwn.college{0pUgg-thcTljZqEwTt6FVzvQRG1.dVDMywiMwkjNzEzW}`

***

# 18. Memory sum
Here we learn how to utilise offsets as memory is linear, so we can access specific bits of a word by just offsetting it from the start by n degrees. We're to load two consecutive quad words from the address stored in rdi, then calculate the sum of the previous steps' quad words and finally store the sum at the address in rsi.

```asm
mov rax, [rdi]        
mov rbx, [rdi + 8]    
add rax, rbx          
mov [rsi], rax      
```

## Flag
`pwn.college{g5L_oUHoMpVgjXuw-eln-vhbgiA.dZDMywiMwkjNzEzW}`

***

# 19. Stack Subtraction
This challenge focuses on the memory stack, utilising the functions to push and pop values from it as well as the stack pointer register which is used to point to the latest location inside the stack. We're to take the top value of the stack, subtract rdi from it, then put it back. 

```asm
pop rax        
sub rax, rdi   
push rax       
```

## Flag
`pwn.college{IG0AFGXLdHfdBWY_wk_Bfycnsg-.ddDMywiMwkjNzEzW}`


***

# 20. Swap Stack values
Now using only push and pop, we're to swap the values stored in rdi and rsi. This leverages the stack's LIFO property.

```asm
push rdi
push rsi
pop rdi
pop rsi
```

## Flag
`pwn.college{sLE0W_nZArOG7QFK5C2HRt3SQlS.dhDMywiMwkjNzEzW}`

***

# 21. Average Stack values
We're to ustilise the rsp register to calculate the average of 4 consecutive quad words stored on the stack and then push the average on the stack.

```asm
mov rax, [rsp]        
add rax, [rsp + 8]    
add rax, [rsp + 16]   
add rax, [rsp + 24]   
shr rax, 2            
push rax              
```

Shifting right by 2 essentially performs the equivalent of dividing by 4. 

## Flag
`pwn.college{8dmFqWKdc_TI1YmQUv7bVf2vSpH.dlDMywiMwkjNzEzW}`

***

# 22. Absolute Jump
Here we learn the ustilisation of the jmp command as well as learning the rip instruction pointer. We learn about unconditional and conditional jumps and also Relative jumps, Absolute jumps and Indirect jumps. We're to Jump to the absolute address 0x403000

```asm
mov rax, 0x403000
jmp rax
```

## Flag
`pwn.college{4YWHcWC3hF_1-_l-r76cL13WZxP.QX1EDOzwiMwkjNzEzW}`

***

# 23. Relative Jump
Here we learn how to perform a realtive jump as well as learning about labels, noperation, and .rept (Repeat Directive). This took a while as nasm did not register how to process the repeat directive as I wasn't using GAS so I had to tweak the code.

```asm
jmp target
%rep 0x51
    nop
%endrep
target:
    mov rax, 1
```
We repeat nop for 0x51 times to give the idea of doing the jump for 0x51 bytes. 

## Flag
`pwn.college{oAdDcDmX6qezKbGmYD5WD0VLr4V.QX2EDOzwiMwkjNzEzW}`


***

# 24. Jump Trampoline
We're to Create a two jump trampoline:
Make the first instruction in your code a jmp.
Make that jmp a relative jump to 0x51 bytes from its current position.
At 0x51, write the following code:
Place the top value on the stack into register rdi.
jmp to the absolute address 0x403000.

```asm
jmp trampoline
%rep 0x51
    nop
%endrep

trampoline:
    pop rdi
    mov rax, 0x403000
    jmp rax
```

## Flag
`pwn.college{sZIfIVWcY8cQRSHBZVSduwOMudX.dFTMywiMwkjNzEzW}`


***

# 25. Conditional Jump.
We learn about zero flags as well as implementing a proper conditional statement via the use of the jmp command and the cmp command. We're to implement the following logic using jmp(any variant) and cmp

```
if [x] is 0x7f454c46:
    y = [x+4] + [x+8] + [x+12]
else if [x] is 0x00005A4D:
    y = [x+4] - [x+8] - [x+12]
else:
    y = [x+4] * [x+8] * [x+12]
```

The solution is: 

```asm
mov eax, [rdi]
cmp eax, 0x7f454c46
je  elf

cmp eax, 0x5A4D
je  mz

mov eax, [rdi+4]
imul eax, [rdi+8]
imul eax, [rdi+12]
jmp done

elf:
    mov eax, [rdi+4]
    add eax, [rdi+8]
    add eax, [rdi+12]
    jmp done

mz:
    mov eax, [rdi+4]
    sub eax, [rdi+8]
    sub eax, [rdi+12]

done:
```

## Flag
`pwn.college{Ew_eN7KFp_a6Ipwt5WgzQlkfH9y.dJTMywiMwkjNzEzW}`


***

# 26. Indirect Jump
We learn about jump tables, more or less just jumping with offsets. We're to implement the following
```
if rdi is 0:
  jmp 0x40301e
else if rdi is 1:
  jmp 0x4030da
else if rdi is 2:
  jmp 0x4031d5
else if rdi is 3:
  jmp 0x403268
else:
  jmp 0x40332c
```

We're to do the above with the following constraints:

Assume rdi will NOT be negative.
Use no more than 1 cmp instruction.
Use no more than 3 jumps (of any variant).
We will provide you with the number to 'switch' on in rdi.
We will provide you with a jump table base address in rsi.


```asm
cmp rdi, 3
ja  default_case

mov rax, [rsi + rdi*8]
jmp rax

default_case:
    mov rax, [rsi + 4*8]
    jmp rax
```

## Flag
`pwn.college{4P9rPTxWjLD01rPg_EX7SqUVixo.dNTMywiMwkjNzEzW}`


***

# 27. Average Loop
We now progess to loops and how to implement them in asm. We're to use a simulation of a for loop to compute the average of n consecutive quad words, where:
rdi = memory address of the 1st quad word
rsi = n (amount to loop for)
rax = average computed

```asm
loop:
    cmp rcx, rsi
    je  done            
    add rax, [rdi + rcx*8]  
    inc rcx
    jmp loop

done:
    xor rdx, rdx       
    div rsi             
```

The loop summates and done computes the average.

## Flag
`pwn.college{4P9rPTxWjLD01rPg_EX7SqUVixo.dNTMywiMwkjNzEzW}`

***

# 28. Count non-zero 
We're to count the consecutive non-zero bytes in a contiguous region of memory, where:
rdi = memory address of the 1st byte
rax = number of consecutive non-zero bytes
We learn about the general implementation of the while loop using the jmp, call and cmp functions. 

```asm
cmp rdi, rdi
je   done      
loop:
    cmp [dil], 0
    je  done           
    inc rax              
    inc rdi          
    jmp loop

done:
    ; rax contains the count
```
Also sidenote, learnt how to implement comments in asm too. 

## Flag
`pwn.college{UzgyDie4LZBFj98oH_9MGkFgC8r.dRTMywiMwkjNzEzW}`


***

# 29. String lower
We now work with functions in this level, we're provided with a contiguous region of memory again and will loop over each performing a conditional operation till a zero byte is reached, via functions. We use call and ret here. 

```
Please implement the following logic:

str_lower(src_addr):
  i = 0
  if src_addr != 0:
    while [src_addr] != 0x00:
      if [src_addr] <= 0x5a:
        [src_addr] = foo([src_addr])
        i += 1
      src_addr += 1
  return i
```

This also made me laern about the Linux amd64 calling convention. 

```asm
cmp rdi, 0
je  done

loop:
    mov al, [rdi]
    cmp al, 0
    je  done

    cmp al, 0x5A
    ja  next

    push rdi
    xor edi, edi
    mov dil, al
    mov rax, 0x403000       ; calling foo
    call rax
    pop rdi

    mov [rdi], al
    inc rcx

next:
    inc rdi
    jmp loop

done:
    mov rax, rcx
    ret
```

## Flag
`pwn.college{8FoRAeg2r5LwX0regaPrP4cW3Xl.dVTMywiMwkjNzEzW}`


***

# 30. Most Common Byte
We learn about rbp, the Stack Base Pointer, used to restore the stack to where it originally was. 

We're to implement
```
most_common_byte(src_addr, size):
  i = 0
  while i <= size-1:
    curr_byte = [src_addr + i]
    [stack_base - curr_byte * 2] += 1
    i += 1

  b = 0
  max_freq = 0
  max_freq_byte = 0
  while b <= 0xff:
    if [stack_base - b * 2] > max_freq:
      max_freq = [stack_base - b * 2]
      max_freq_byte = b
    b += 1

  return max_freq_byte
```

Along with assumptions and constraints.

```asm
sub rsp, 512
xor rcx, rcx
z:
    mov word [rsp+rcx*2], 0
    inc rcx
    cmp rcx, 256
    jne z

    xor rcx, rcx
c:
    cmp rcx, rsi
    je f

    mov al, [rdi+rcx]
    mov rdx, rax
    and rdx, 0xff
    add word [rsp+rdx*2], 1

    inc rcx
    jmp c

f:
    xor rcx, rcx
    xor rbx, rbx
    xor rax, rax

m:
    cmp rcx, 256
    je e

    mov dx, [rsp+rcx*2]
    cmp rdx, rbx
    jbe n

    mov rbx, rdx
    mov rax, rcx

n:
    inc rcx
    jmp m

e:
    add rsp, 512
    ret
```

The function begins by subtracting 512 bytes from rsp, reserving space on the stack for a counting table. That size is chosen deliberately: there are 256 possible byte values, and each counter is stored as a 16-bit word, which is sufficient because the problem guarantees no byte occurs more than 0xffff times. Since stack memory is uninitialized, the first loop walks from 0 to 255 and manually clears each 2-byte counter at [rsp + rcx*2], ensuring a known starting state.
After initialization, the function enters the counting phase. Using rcx as an index, it iterates from 0 up to size - 1, reading each byte from the buffer at [rdi + rcx]. Throughout this phase, the source buffer is never modified; it is only read, satisfying the immutability requirement.
Once all bytes have been counted, the function resets its loop variables and scans the counting table to determine the most frequent byte. It again iterates from 0 to 255, loading each counter from [rsp + rcx*2] and comparing it against the current maximum frequency stored in rbx. If the new count is strictly greater, the function updates both rbx (the maximum frequency) and rax (the byte value that produced it). Using an unsigned comparison ensures correctness, and skipping updates on equal counts preserves the first byte with the maximum frequency.
Finally, the function restores the stack by adding back the same 512 bytes it reserved at the start and returns normally. At that point, rax contains the byte value with the highest frequency, exactly as specified.

## Flag
`pwn.college{Inx3GB86ws9EfXFr1rBkRyACUil.dZTMywiMwkjNzEzW}`


***