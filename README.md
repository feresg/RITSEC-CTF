# RITSEC CTF 2018 Writeup
*Write up by: Feres Gaaloul (https://github.com/feresg)
My first CTF Writeup, be gentle!*

**Challenges solved:**

| Challenge               | Category  | Points |
|-------------------------|-----------|--------|
| Who drew on my program? | Crypto    | 350    |
| I am a stegosaurus      | Forensics | 250    |
| The tangled web         | Web       | 200    |
| Space force             | Web       | 100    |
| Talk to me              | Misc      | 10     |
| Litness test            | Misc      | 1      |

## Who drew on my program?

**Hint:** I don't remember what my IV was I used for encryption and then someone painted over my code :(. Hopefully somebody else wrote it down!

**[File:](https://github.com/feresg/RITSEC-CTF/blob/master/crypto.png)** 

![enter image description here](https://github.com/feresg/RITSEC-CTF/raw/master/crypto.png)

**Solving the challenge:**

This image represents a python script for encrypting a string using the AES/CBC encryption.
Here's how the algorithm decrypts data:

![enter image description here](https://i.stack.imgur.com/dFjX3.png)

Some variables are either hidden or partially present.

Complete data : 
* Message/Plaintext : 32 byte message

Partial data: 
* Encryption key: missing 2 bytes (14 bytes present)
* Cipher text: Since the message is 32 bytes, the ciphertext is 32 bytes as well. the `binascii.hexlify()` method in python turns it into its hexadecimal representation, making it twice as long. We have the complete second block of 16 bytes, but the first block only has bytes 0, 14 and 15

Missing data:
* Initialization Vector (IV)

In order to resolve the challenge we need to find the missing data. We can do that by reversing the process of the algorithm.

**Finding the correct keys:**

1- We create a list of all possible chars
2- Nested for loops allows us to create all possible 2 char combos to finish the missing key combos (128*128 = 16384 possible combos) 
possible_key = partial_key + ch1 + ch2
3- We decrypt cipher_block_1 only using AES ECB decryption. We obtain decrypted_cipher_block_1
4- message[16:] = decrypted_block_1 XOR cipher_block_0
but we only have 3 bytes of cipher block 0. We can check if our current key is correct by applying XOR only on the first and last (and possibly 14th) byte of both decrypted_block_1 and cipher_block_0. If we get the same results as the characters 'r' and '!' respectively, we can consider the currect key as correct.

**Finding the correct IVs:**

1- Now that we have the correct key(s) we can complete the previous cipher block (cipher_block_0)
message[16:] = decrypted_block_1 XOR cipher_block_0
is equivalent to
cipher_block_0 = decrypted_block_1 XOR mesage[16:]
2- Now we can guess the possible IVs
message[:16] = decrypted_block_0 XOR IV
IV = decrypted_block_0 XOR message[:16]
decrypted_block_0 is found by applying AES ECB decryption on the filtered keys

The IV is our flag!
[**Python script (use python2)**](https://github.com/feresg/RITSEC-CTF/blob/master/cipher.py)  

```
import binascii
from Crypto.Cipher import AES

def xor_blocks(b1, b2):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(b1, b2))

def encrypt(m, p, iv):
    aes = AES.new(p, AES.MODE_CBC, iv)
    return aes.encrypt(m)

def decrypt_block(c, k):
    aes = AES.new(k, AES.MODE_ECB)
    return aes.decrypt(c)


# Partial key
partial_key = "9aF738g9AkI112"
# Secret message
message = "The message is protected by AES!"
# Cipher block 1
cipher_block_1 = binascii.unhexlify('808e200a54806b0e94fb9633db9d67f0')
# Known cipher block 0 bytes
partial_cipher_block_0 = {
            0: "\x9E",
            14: "\x43",
            15: "\x6A"
}

# List of all chars
chars = [chr(x) for x in range(128)]

# Finding correct keys:
possible_keys = []
for ch1 in chars:
    for ch2 in chars:
        # Create 16 bytes key
        possible_key = partial_key + ch1 + ch2
        # Decrypt last block
        decrypted_block_1 = decrypt_block(cipher_block_1, possible_key)
        # Check if XORing first cipher block with decrypted second block results in correct message for first and last bit
        check_first_bit = message[16] == chr(ord(decrypted_block_1[0]) ^ ord(partial_cipher_block_0[0]))
        check_last_bit = message[31] == chr(ord(decrypted_block_1[15]) ^ ord(partial_cipher_block_0[15]))
        if(check_first_bit and check_last_bit):
            possible_keys.append(possible_key)
print(possible_keys)

# Now we have complete key, complete cipher block 1
# We can guess cipher block 0
# Cipher block 0 = Decrypted cipher block 1 XOR message[16:]
possible_ivs = []
for correct_key in possible_keys:
    decrypted_block_1 = decrypt_block(cipher_block_1, correct_key)
    cipher_block_0 = xor_blocks(decrypted_block_1, message[16:])

    # Now that we have the complete cipher block 0 and key
    # We can guess the IV of the encryption
    # IV = Decrypted cipher block 0 XOR message[:16]
    decrypted_block_0 = decrypt_block(cipher_block_0, correct_key)
    iv = xor_blocks(decrypted_block_0, message[:16])
    possible_ivs.append(iv)

print(possible_ivs)

```

**Output:**

![enter image description here](https://github.com/feresg/RITSEC-CTF/raw/master/screenshot_cipher.png)

Et voila!


## I am a Stegosaurus

**Hint:** Look Closely

**[File:](https://github.com/feresg/RITSEC-CTF/blob/master/stegosaurus.png)**

**Solving the challenge:**

This file seems to have a signature of a PNG file it isn't an archive in disguise. Applying [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html) shows us that part of the PNG signature is corrupted (*CRC error in chunk IHDR*).

![enter image description here](https://github.com/feresg/RITSEC-CTF/raw/master/screenshot_forensics.png)

I found this C program ([pngcsum](http://schaik.com/png/pngcsum.html)) online that fixes a png header because i'm too lazy to code it myself and reuse is great! 

![enter image description here](https://github.com/feresg/RITSEC-CTF/raw/master/screenshot_forensics2.png)

The fixed image contains the flag! Yay!

![enter image description here](https://github.com/feresg/RITSEC-CTF/raw/master/stegosaurus_fixed.png)

## The tangled web

**Website:** [fun.ritsec.club:8007](fun.ritsec.club:8007)

**Solving the challenge:**

Buddha himself Nabil Houidi stumbled on this char sequence while reading the source code of one of the many links that this unfunny rick rolling website takes you to.

![enter image description here](https://github.com/feresg/RITSEC-CTF/raw/master/screenshot_web.png)

Applying base64 decoding on that char sequence gives us the flag!

![enter image description here](https://github.com/feresg/RITSEC-CTF/raw/master/screenshot_web2.png)

## Space Force

**Website:**  [fun.ritsec.club:8005](fun.ritsec.club:8005)

**Hint:** The Space Force has created a portal for the public to learn about and be in awe of our most elite Space Force Fighters. Check it out at  `fun.ritsec.club:8005`!

**Solving the challenge:**

Solved again by Nabil Houidi (SQL Injection)


## Talk to me

Free flag just for joining the Discord chat

## Litness test

free flag in the hint!
