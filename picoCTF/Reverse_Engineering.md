# 1. GDB Baby Step 1 
Can you figure out what is in the eax register at the end of the main function? Put your answer in the picoCTF flag format: picoCTF{n} where n is the contents of the eax register in the decimal number base. If the answer was 0x11 your flag would be picoCTF{17}. Disassemble this.

## Solution: 
Here we ustilise the IDA disassembler to view the contents of the file. Using which, we look into the main function via asm or graph view on IDA and extract the value of eax. Here the mov command directs the value on the right hand side into the register eax, the value followed by mov command is what is copied into eax after the main function call. i.e 86342h. This is in hexadecimal. We furthermore place this value into cyberchef to convert it from hexadecimal to decimal. 
Attached below is the graph view of the main function in the IDA disassembler. 

![](IMAGES/screenshot.png "IDA graph view.")

## Flag 
```
picoCTF{549698}
```
## Concepts learnt:
This challenge inundates us into the utilisation of disassembly software to reverse engineer functions. This was a simple challenge which accquainted us to the disassembler and undertand the various sections to look out for. A disassembler generates assembly language source code from machine-executable code. Here we learnt the use of mov in asm interpretation and how it correlates into placing a value into a register(here, eax). Note that in assembly language, a register is a small, high-speed storage location, this is a temporary memory which is manipulated in processes. 

## Notes: 
I has initially places the literal file/memory address of the eax register into consideration, this was a crucial error and a misstep in me not reading the problem statement correctly. 

## Resources: 

IDA Free 9.0

Cyberchef (https://cyberchef.org/)

***

# 2. ARMssembly 1
For what argument does this program print `win` with variables 87, 3 and 3? File: chall_1.S Flag format: picoCTF{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be picoCTF{0055aabb})

## Solution
This requires a broader knowledge of the keywords in an assembly script, here we're given a raw assembly script for an x64 ARM processor. We must analyse the raw code to see what the program check and returns a "win" for. We must also have to convert that argument into hex (the format specifies 32bit). On a look into the code we see a few primary functions which eventually compute((87 << 3) / 3) - input and crossreferences them with zero and returns the winning statement when true. Thus on calculation we get 232 to be the winning argument.

## Flag:
```
picoCTF{000000e8}
```

## Concepts learnt
Here, as in the previous challenge, mov copies a value into a register. lsl here means "logical shift left", performing a binary shift (<<) equivalent to multiplying by 2^(shift amount). sdiv performs signed integer division of two registers. Sub is straightforward, it simply subtracts two registers. cbz here compares a register's value with zero and branches into a label if true. A label is simply a named location in the program’s code (they end with a :). 

## Notes:
This was a fundamental case of me not paying attention to what's in front of me, I had initially seen that it was not possible to run the dissassembly software on the code and began looking into docker use to emulate a linux platform to disassemble the program. All while not properly looking into the program itself. The entire solution is in the program itself. 

## Resources
https://azeria-labs.com/arm-instruction-set-part-3/


***

# 3. Vault Door 3
This vault uses for-loops and byte arrays. The source code for this vault is here: VaultDoor3.java

## Solution
Here upon analysis of the java source code we get the following string from which the password/flag is generated.
```
jU5t_a_sna_3lpm12g94c_u_4_m7ra41
```
The code switches this target string in accordance to its position and modifies characters by varying degrees wrt the position in the buffer character array, here we're taking characters from the string but rearranging them by this specific permuation.
Now using python (anything works, I just want to learn python so I've taken some external help) to reconstruct the original password from the target. 

```python 
target = "jU5t_a_sna_3lpm12g94c_u_4_m7ra41"  
password = ['?'] * 32
for i in range(0, 8):
    buffer_idx = i
    pwd_idx = i
    password[pwd_idx] = target[buffer_idx]
for i in range(8, 16):
    buffer_idx = i
    pwd_idx = 23 - i
    password[pwd_idx] = target[buffer_idx]
i = 16
while i < 32:
    buffer_idx = i
    pwd_idx = 46 - i
    password[pwd_idx] = target[buffer_idx]
    i += 2
i = 31
while i >= 17:
    buffer_idx = i
    pwd_idx = i
    password[pwd_idx] = target[buffer_idx]
    i -= 2

recovered = ''.join(password)
print("flag: picoCTF{" + recovered + "}")
```

## Flag:
```
picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_c79a21}
```

## Concepts learnt
This required an understanding of how the program works, here the user input password is run into an empty buffer container and is subjected to multiple iterations of loops that alter the character in the input string and copies them into buffer. At the end a check is done with buffer against a target string and the program outputs a vaild output if they are equal. Here I've also learnt a little about python, utilised loops in python along with indexes in arrays. 

## Notes:
Note to report here, the java file did not require any dissassembly, only took time to contruct the python program

## Resources
https://www.w3schools.com/python/python_for_loops.asp
https://www.w3schools.com/python/python_while_loops.asp
