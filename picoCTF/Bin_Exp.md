# 1. Buffer Overflow 0
Let's start off simple, can you overflow the correct buffer? The program is available _here_. You can view source _here_.
After launching instance - Connect using: nc saturn.picoctf.net 57780

## Solution
Upon analysis of the C source code, we see the function 'sigsegv_handler' which prints that secret if the program receives a segmentation fault (SIGSEGV). the challenge hint and the gets man page tells us that gets is an unsafe manner in which info is obtained and can be exploited by overflow attacks. Below is the manpage of gets

```
 The gets() function cannot be used securely.  Because of its lack of
     bounds checking, and the inability for the calling program to reliably
     determine the length of the next incoming line, the use of this function
     enables malicious users to arbitrarily change a running program's
     functionality through a buffer overflow attack.  It is strongly suggested
     that the fgets() function be used in all cases.  (See the FSA.)
```

The program also uses strcpy to move the obtained string into a much smaller buffer (16-byte). Therefore, if our input is above 16 bytes, we'll get the flag from the global flag buffer as SIGSEGV will be called (buffer overflows). 

Calling the nc connection we pass a relatively long string and Voilà.

![](IMAGES/manpage.png "Gets manpage warning")


## Flag: 
```
picoCTF{ov3rfl0ws_ar3nt_that_bad_ef01832d}
```

## Concepts learnt
This challenge required me to look into buffer overflows in C, I've looked into SIGSEGV and nc connections along with the gets command (and why it's not preffered and exposes a crucial vulnerability in the challenge). 


## Notes
Note to note here, challenge was self explainatory. Few trial and errors eventually gave the flag

## References
https://en.wikipedia.org/wiki/Segmentation_fault
https://www.varonis.com/blog/netcat-commands
https://stackoverflow.com/questions/1694036/why-is-the-gets-function-so-dangerous-that-it-should-not-be-used

***

# 2. Format String 0
Can you use your knowledge of format strings to make the customers happy? Download the binary *here*. Download the source *here*.
After running instance - Conncect via netcat 

## Solution
Just as the previous challenge, the source code utilises the SIGSEGV signal which prints the flag when activated. In the first interaction after the main function sets the program sandbox, serve_patrick() is called and it prompts us as the user and takes a string as choice1. But then we see this.

```C
int count = printf(choice1);
```

This line of code passes our string directly as the format string rather than as data. Therefore we see that any % sequences in the input will be interpreted by printf as format specifiers. Looking into the options their actual size are all the same as strings, the function only continues to the next "customer" if the string passed is greater than 64 bytes. The option "Gr%114d_Cheese" works here as %114, although not an actual format specifier in C When used like %114d, the 114 is a minimum field width. It tells printf to print the value in a field at least 114 characters wide and thus greatly increasing our size when passed into the size variable.

With that serve_bob() is called where we're told to deliver an "outrageous order". The source code has no checks, except for the previously declared SIGSEGV, so now we have to look for a string to pass as a format string to "crash" the program. Passing "Cla%sic_Che%s%steak" to the prompt, as %s is a format specifier, this crashes the program and gives us our flag. This call of string format specifiers which don't really interpet anything causes a segmentation error and causes the SIGSEGV function to activate and print our flag.

![](IMAGES/format_string.png "Full netcat connection")

## Flag:
```
picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_dc0f36c4}
```

## Concepts Learnt
Format specifiers are the main takeaway here, this challenge gives us an idea of how they work and how they're subtly used in completing the challenge. Also looked into the nuances of the printf command during variable initialisation. 

## Notes
Quite an easy challenge, only required two tries. 

## References
https://www.geeksforgeeks.org/c/format-specifiers-in-c/

***


# 3. Clutter overflow
Clutter, clutter everywhere and not a byte to use. nc mars.picoctf.net 31890

## Solution
Looking into the nc conntection, we see this

![](IMAGES/testpay.png "test payload to nc")

Passing the payload also gives us a 0x0 which does not align with the given code of '0xdeadbeef'. Looking into the C source for a bit we see that the program uses gets, which is vulnerable to a bufferoverflow and can be used to exploit the system and convert the stack to store the hex code of deadbeef. Being given the hint of using pwntools we script this using p64 and remote.

```py
from pwn import remote, p64

r = remote("mars.picoctf.net", 31890)
r.sendline(b"A"*0x108 + p64(0xdeadbeef))
print(r.recvall(timeout=4).decode(errors="ignore"))
r.close()
```

Saving this as `exploit.py` we further pass this in the terminal

```zsh
python3 exploit.py
```

Giving us the flag.


## Flag:
```
picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
```

## Concepts learnt
Here p64 passes a little-endian representation of the hex code after overflowing the buffer (A is repeated 0x108 times i.e 264), rewriting it with the representation of `0xdeadbeef`. 
Remote here estabilshes a connection automatically to the challenge server via code. (no need to nc in terminal)
`r.recvall()` reads everything the remote end sends until the connection closes. 
`.decode(errors="ignore")` converts the raw bytes to a string for printing
`.sendline()` just processes and passes our payload to the nc connection, essentially doing the typing job
b"..." produces a bytes object to pass raw binary data

The reason why we script this is because of the fact that we can't pass the raw binary data of the converted text as ASCII into the nc connection and hence requires so. I think printf also works here as it passes data as raw binary but I couldn't seem to get it to pipe into the nc connection.  

## Notes
This was a step more difficult for me compared to previous challenges. I wasn't familiar with how to pass the hex equivalent to the buffer so all I got were iterations of 0x1414141 into my code as only A's filled the stack after overflow. This was quite complex and had me delve into little endian representation as well as the pwntools catalogue, eventually forcing me to script the paylaod passing. 

## References
https://docs.pwntools.com/en/latest/util/packing.html#pwnlib.util.packing.p64
docs.pwntools.com/en/stable/tubes/sockets.html#pwnlib.tubes.remote.remote
https://www.geeksforgeeks.org/dsa/little-and-big-endian-mystery/
https://guyinatuxedo.github.io/02-intro_tooling/pwntools/index.html
https://en.wikipedia.org/wiki/Endianness
