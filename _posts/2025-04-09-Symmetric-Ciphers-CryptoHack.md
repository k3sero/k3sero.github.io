---
title: Symmetric Ciphers - CryptoHack
author: Kesero
description: Soluciones a los retos de la categoría Symmetric Ciphers de CryptoHack
date: 2025-04-09 10:00:00 +0000
categories: [CryptoHack, Cifrados Simétricos]
tags: [CryptoHack]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/CryptoHack/img/2.png?raw=true
  lqip: 
  alt: 
comments: true
---

En este apartado, estaré subiendo las soluciones para los retos de la categoría "Cifrados Simétricos" de CryptoHack.

Los subapartados que se tratarán son `How AES Works`, `Symmetric Starter`, `Block Ciphers`, `Stream Ciphers`, `Padding Attacks`, `Authenticated Encryption`, `Linear CryptAnalysis`

## Introduction

Symmetric-key ciphers are algorithms that use the same key both to encrypt and decrypt data. The goal is to use short secret keys to securely and efficiently send long messages.

The most famous symmetric-key cipher is Advanced Encryption Standard ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)), standardised in 2001. It's so widespread that modern processors even contain [special instruction sets](https://en.wikipedia.org/wiki/AES_instruction_set) to perform AES operations. The first series of challenges here guides you through the inner workings of AES, showing you how its separate components work together to make it a secure cipher. By the end you will have built your own code for doing AES decryption!

We can split symmetric-key ciphers into two types, block ciphers and stream ciphers. Block ciphers break up a plaintext into fixed-length blocks, and send each block through an encryption function together with a secret key. Stream ciphers meanwhile encrypt one byte of plaintext at a time, by XORing a pseudo-random keystream with the data. AES is a block cipher but can be turned into a stream cipher using modes of operation such as CTR.

Block ciphers only specify how to encrypt and decrypt individual blocks, and a [mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) must be used to apply the cipher to longer messages. This is the point where real world implementations often fail spectacularly, since developers do not understand the subtle implications of using particular modes. The remainder of the challenges see you attacking common misuses of various modes.


## How AES Works

### Keyed Permutations

AES, like all good block ciphers, performs a "keyed permutation". This means that it maps every possible input block to a unique output block, with a key determining which permutation to perform.

  A "block" just refers to a fixed number of bits or bytes, which may represent any kind of data. AES processes a block and outputs another block. We'll be specifically talking the variant of AES which works on 128 bit (16 byte) blocks and a 128 bit key, known as AES-128.

Using the same key, the permutation can be performed in reverse, mapping the output block back to the original input block. It is important that there is a one-to-one correspondence between input and output blocks, otherwise we wouldn't be able to rely on the ciphertext to decrypt back to the same plaintext we started with.

What is the mathematical term for a one-to-one correspondence?

#### Flag

`crypto{bijection}`

### Resisting Bruteforce

If a block cipher is secure, there should be no way for an attacker to distinguish the output of AES from a [random permutation](https://en.wikipedia.org/wiki/Pseudorandom_permutation) of bits. Furthermore, there should be no better way to undo the permutation than simply bruteforcing every possible key. That's why academics consider a cipher theoretically "broken" if they can find an attack that takes fewer steps to perform than bruteforcing the key, even if that attack is practically infeasible.

How difficult is it to bruteforce a 128-bit keyspace? [Somebody estimated](https://crypto.stackexchange.com/a/48669) that if you turned the power of the entire Bitcoin mining network against an AES-128 key, it would take over a hundred times the age of the universe to crack the key.

It turns out that there is [an attack (Biclique)](https://en.wikipedia.org/wiki/Biclique_attack) on AES that's better than bruteforce, but only slightly – it lowers the security level of AES-128 down to 126.1 bits, and hasn't been improved on for over 8 years. Given the large "security margin" provided by 128 bits, and the lack of improvements despite extensive study, it's not considered a credible risk to the security of AES. But yes, in a very narrow sense, it "breaks" AES.

Finally, while quantum computers have the potential to completely break popular public-key cryptosystems like RSA via [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm), they are thought to only cut in half the security level of symmetric cryptosystems via [Grover's algorithm](https://en.wikipedia.org/wiki/Grover's_algorithm). This is one reason why people recommend using AES-256, despite it being less performant, as it would still provide a very adequate 128 bits of security in a quantum future.

What is the name for the best single-key attack against AES?

#### Flag

`crypto{biclique}`

### Structure of AES

To achieve a keyed permutation that is infeasible to invert without the key, AES applies a large number of ad-hoc mixing operations on the input. This is in stark contrast to public-key cryptosystems like RSA, which are based on elegant individual mathematical problems. AES is much less elegant, but it's very fast.

At a high level, AES-128 begins with a "key schedule" and then runs 10 rounds over a state. The starting state is just the plaintext block that we want to encrypt, represented as a 4x4 matrix of bytes. Over the course of the 10 rounds, the state is repeatedly modified by a number of invertible transformations.

Each transformation step has a defined purpose based on theoretical properties of secure ciphers established by Claude Shannon in the 1940s. We'll look closer at each of these in the following challenges.

![Schema](https://cryptohack.org/static/img/aes/Structure.png)

1. KeyExpansion or Key Schedule

From the 128 bit key, 11 separate 128 bit "round keys" are derived: one to be used in each AddRoundKey step.

2. Initial key addition

AddRoundKey - the bytes of the first round key are XOR'd with the bytes of the state.

3. Round - this phase is looped 10 times, for 9 main rounds plus one "final round"

a) SubBytes - each byte of the state is substituted for a different byte according to a lookup table ("S-box").

b) ShiftRows - the last three rows of the state matrix are transposed—shifted over a column or two or three.

c) MixColumns - matrix multiplication is performed on the columns of the state, combining the four bytes in each column. This is skipped in the final round.

d) AddRoundKey - the bytes of the current round key are XOR'd with the bytes of the state.

Included is a bytes2matrix function for converting our initial plaintext block into a state matrix. Write a matrix2bytes function to turn that matrix back into bytes, and submit the resulting plaintext as the flag.

#### Solver

```py
def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

matrix = [
    [99, 114, 121, 112],
    [116, 111, 123, 105],
    [110, 109, 97, 116],
    [114, 105, 120, 125],
]
print(matrix2bytes(matrix))
```

#### Flag
`crypto{inmatrix}`

### Round Keys

We're going to skip over the finer details of the KeyExpansion phase for now. The main point is that it takes in our 16 byte key and produces 11 4x4 matrices called "round keys" derived from our initial key. These round keys allow AES to get extra mileage out of the single key that we provided.

The initial key addition phase, which is next, has a single AddRoundKey step. The AddRoundKey step is straightforward: it XORs the current state with the current round key.

![Round Keys](https://cryptohack.org/static/img/aes/AddRoundKey.png)

AddRoundKey also occurs as the final step of each round. AddRoundKey is what makes AES a "keyed permutation" rather than just a permutation. It's the only part of AES where the key is mixed into the state, but is crucial for determining the permutation that occurs.

As you've seen in previous challenges, XOR is an easily invertible operation if you know the key, but tough to undo if you don't. Now imagine trying to recover plaintext which has been XOR'd with 11 different keys, and heavily jumbled between each XOR operation with a series of substitution and transposition ciphers. That's kinda what AES does! And we'll see just how effective the jumbling is in the next few challenges.

Complete the add_round_key function, then use the matrix2bytes function to get your next flag.

#### Solver
```py
state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def add_round_key(s, k):
    return [[sss^kkk for sss, kkk in zip(ss, kk)] for ss, kk in zip(s, k)]

print(add_round_key(state, round_key))
print(matrix2bytes(add_round_key(state, round_key)))
```

#### Flag
`crypto{r0undk3y}`

### Confusion through Substitution

The first step of each AES round is SubBytes. This involves taking each byte of the state matrix and substituting it for a different byte in a preset 16x16 lookup table. The lookup table is called a "Substitution box" or "S-box" for short, and can be perplexing at first sight. Let's break it down.

![Confusion](https://cryptohack.org/static/img/aes/Substitution.png)

In 1945 American mathematician Claude Shannon published a groundbreaking paper on Information Theory. It identified "confusion" as an essential property of a secure cipher. "Confusion" means that the relationship between the ciphertext and the key should be as complex as possible. Given just a ciphertext, there should be no way to learn anything about the key.

If a cipher has poor confusion, it is possible to express a relationship between ciphertext, key, and plaintext as a linear function. For instance, in a Caesar cipher, ciphertext = plaintext + key. That's an obvious relation, which is easy to reverse. More complicated linear transformations can be solved using techniques like Gaussian elimination. Even low-degree polynomials, e.g. an equation like x^4 + 51x^3 + x, can be solved efficiently using [algebraic methods](https://math.stackexchange.com/a/1078515). However, the higher the degree of a polynomial, generally the harder it becomes to solve – it can only be approximated by a larger and larger amount of linear functions.

The main purpose of the S-box is to transform the input in a way that is resistant to being approximated by linear functions. S-boxes are aiming for high non-linearity, and while AES's one is not perfect, it's pretty close. The fast lookup in an S-box is a shortcut for performing a very nonlinear function on the input bytes. This function involves taking the modular inverse in the [Galois field 2**8](https://www.samiam.org/galois.html) and then applying an affine transformation which has been tweaked for maximum confusion. The simplest way to express the function is through the following high-degree polynomial:

![poly](https://cryptohack.org/static/img/aes/SBoxEq.png)

To make the S-box, the function has been calculated on all input values from 0x00 to 0xff and the outputs put in the lookup table.

Implement sub_bytes, send the state matrix through the inverse S-box and then convert it to bytes to get the flag.

#### Solver

```py
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

state = [
    [251, 64, 182, 81],
    [146, 168, 33, 80],
    [199, 159, 195, 24],
    [64, 80, 182, 255],
]

def sub_bytes(s, sbox=s_box):
    return list(map(lambda x: sbox[x], sum(s, [])))

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

confusion = sub_bytes(state, sbox=inv_s_box)
flag = ""

for element in confusion:
    flag += chr(element)

print(f"\n[+] Flag: {flag}")
```

#### Flag
`crypto{lin34rly}`


### Diffusion through Permutation

We've seen how S-box substitution provides confusion. The other crucial property described by Shannon is "diffusion". This relates to how every part of a cipher's input should spread to every part of the output.

Substitution on its own creates non-linearity, however it doesn't distribute it over the entire state. Without diffusion, the same byte in the same position would get the same transformations applied to it each round. This would allow cryptanalysts to attack each byte position in the state matrix separately. We need to alternate substitutions by scrambling the state (in an invertible way) so that substitutions applied on one byte influence all other bytes in the state. Each input into the next S-box then becomes a function of multiple bytes, meaning that with every round the algebraic complexity of the system increases enormously.

An ideal amount of diffusion causes a change of one bit in the plaintext to lead to a change in statistically half the bits of the ciphertext. This desirable outcome is called the [Avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect).

The ShiftRows and MixColumns steps combine to achieve this. They work together to ensure every byte affects every other byte in the state within just two rounds.

ShiftRows is the most simple transformation in AES. It keeps the first row of the state matrix the same. The second row is shifted over one column to the left, wrapping around. The third row is shifted two columns, the fourth row by three. Wikipedia puts it nicely: "the importance of this step is to avoid the columns being encrypted independently, in which case AES degenerates into four independent block ciphers."

![photo](https://cryptohack.org/static/img/aes/ShiftRows.png)

The diagram (and the AES specification) show the ShiftRows operation occuring in column-major notation. However, the sample code below uses row-major notation for the state matrix as it is more natural in Python. As long as the same notation is used each time the matrix is accessed, the final result is identical. Due to access patterns and cache behaviour, using one type of notation can lead to better performance.

MixColumns is more complex. It performs Matrix multiplication in Rijndael's Galois field between the columns of the state matrix and a preset matrix. Each single byte of each column therefore affects all the bytes of the resulting column. The implementation details are nuanced; [this page](https://www.samiam.org/mix-column.html) and [Wikipedia](https://en.wikipedia.org/wiki/Rijndael_MixColumns) do a good job of covering them.

![photo2](https://cryptohack.org/static/img/aes/MixColumns.png)

We've provided code to perform MixColumns and the forward ShiftRows operation. After implementing inv_shift_rows, take the state, run inv_mix_columns on it, then inv_shift_rows, convert to bytes and you will have your flag.

#### Solver
```py
def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def inv_shift_rows(s):
    s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
    s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
    s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3] 

# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])

def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

state = [
    [108, 106, 71, 86],
    [96, 62, 38, 72],
    [42, 184, 92, 209],
    [94, 79, 8, 54],
]
inv_mix_columns(state)
inv_shift_rows(state)
print(matrix2bytes(state))


```

#### Flag
`crypto{d1ffUs3R}`


### Bringing It All Together

Apart from the KeyExpansion phase, we've sketched out all the components of AES. We've shown how SubBytes provides confusion and ShiftRows and MixColumns provide diffusion, and how these two properties work together to repeatedly circulate non-linear transformations over the state. Finally, AddRoundKey seeds the key into this substitution-permutation network, making the cipher a keyed permutation.

Decryption involves performing the steps described in the "Structure of AES" challenge in reverse, applying the inverse operations. Note that the KeyExpansion still needs to be run first, and the round keys will be used in reverse order. AddRoundKey and its inverse are identical as XOR has the self-inverse property.

We've provided the key expansion code, and ciphertext that's been properly encrypted by AES-128. Copy in all the building blocks you've coded so far, and complete the decrypt function that implements the steps shown in the diagram. The decrypted plaintext is the flag.

Yes, you can cheat on this challenge, but where's the fun in that?

The code used in these exercises has been taken from Bo Zhu's super simple Python AES implementation, so we've reproduced the license here.

Resource: [Rolling your own crypto: Everything you need to build AES from scratch](https://github.com/francisrstokes/githublog/blob/main/2022/6/15/rolling-your-own-crypto-aes.md)"

### Solver

```py
N_ROUNDS = 10

key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'

def expand_key(master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def add_round_key(s, k):
    return [[sss^kkk for sss, kkk in zip(ss, kk)] for ss, kk in zip(s, k)]

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

def sub_bytes(s, sbox=s_box):
    return list(map(lambda x: sbox[x], sum(s, [])))

def inv_sub_bytes(s, sbox=inv_s_box):

    for i in range(len(s)):
        for j in range(len(s[i])):
            s[i][j] = (sbox[s[i][j]])

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def inv_shift_rows(s):
    s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
    s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
    s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3] 

# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])

def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)

def decrypt(key, ciphertext):
    round_keys = expand_key(key) # Remember to start from the last round key and work backwards through them when decrypting

    # Convert ciphertext to state matrix
    state = bytes2matrix(ciphertext)

    # Initial add round key step
    state = add_round_key(state, round_keys[-1])


    for i in range(N_ROUNDS - 1, 0, -1):
        
        inv_shift_rows(state)
        inv_sub_bytes(state)
        state = add_round_key(state, round_keys[i])
        inv_mix_columns(state)

    # Run final round (skips the InvMixColumns step)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    # Convert state matrix to plaintext
    plaintext = matrix2bytes(state)

    return plaintext

print(decrypt(key, ciphertext))
```

#### Flag
`crypto{MYAES128}`

## Symmetric Starter

### Modes of Operation Starter

The previous set of challenges showed how AES performs a keyed permutation on a block of data. In practice, we need to encrypt messages much longer than a single block. A mode of operation describes how to use a cipher like AES on longer messages.

All modes have serious weaknesses when used incorrectly. The challenges in this category take you to a different section of the website where you can interact with APIs and exploit those weaknesses. Get yourself acquainted with the interface and use it to take your next flag!

Play at https://aes.cryptohack.org/passwords_as_keys

![Image](https://aes.cryptohack.org/static/img/aes/ECB_encryption.svg)

Original Code:

```py
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/block_cipher_starter/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/block_cipher_starter/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}
```

#### Solver

Para resolver el reto anterior simplemente tenemos que Obtener la flag encriptada con `encrypt_flag()`, posteriormente desencriptar con la función `decrypt` y por último decodear el plaintext en hexadecimal a bytes. Se debe de realizar mediante la página, ya que no tenemos la clave. De todas formas el script sería el siguiente:

```py
from Crypto.Cipher import AES

def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}

def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}

enc_flag = "bf791ff22629657bedc29428674f686758cc40d847834a4665a205bf540fbdfb"
flag_hex = decrypt(enc_flag)
print(f"\n[+] Flag: {bytes.fromhex(flag_hex)}")
```

#### Flag
`crypto{bl0ck_c1ph3r5_4r3_f457_!}`

### Passwords as Keys

It is essential that keys in symmetric-key algorithms are random bytes, instead of passwords or other predictable data. The random bytes should be generated using a cryptographically-secure pseudorandom number generator (CSPRNG). If the keys are predictable in any way, then the security level of the cipher is reduced and it may be possible for an attacker who gets access to the ciphertext to decrypt it.

Just because a key looks like it is formed of random bytes, does not mean that it necessarily is. In this case the key has been derived from a simple password using a hashing function, which makes the ciphertext crackable.

For this challenge you may script your HTTP requests to the endpoints, or alternatively attack the ciphertext offline. Good luck!

Play at https://aes.cryptohack.org/passwords_as_keys

![Image](https://aes.cryptohack.org/static/img/aes/ECB_encryption.svg)

Original Code:

```py
from Crypto.Cipher import AES
import hashlib
import random


# /usr/share/dict/words from
# https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
with open("/usr/share/dict/words") as f:
    words = [w.strip() for w in f.readlines()]
keyword = random.choice(words)

KEY = hashlib.md5(keyword.encode()).digest()
FLAG = ?


@chal.route('/passwords_as_keys/decrypt/<ciphertext>/<password_hash>/')
def decrypt(ciphertext, password_hash):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/passwords_as_keys/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}
```

#### Solver

Para resolver este reto tenemos que computar todas las llaves proveniente del diciconario de palabras he introducirlas junto al ciphertext obtenido de la función `encrypt_flag()`. Posteriormente pasamos de hexadecimal a bytes y por último podemos guardar todas ellas en un fichero o directamente mostrar solo la que comience por el prefijo `crypto{`

```py
from Crypto.Cipher import AES
import hashlib
import random

def decrypt(ciphertext, key):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}

ct = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"

with open("/usr/share/dict/words") as f:

    for word in f:

        word = word.strip()

        key = hashlib.md5(word.encode()).digest()

        plain_hex = decrypt(ct, key)["plaintext"]
        plaintext = bytes.fromhex(plain_hex)

        if plaintext.startswith(b'crypto{'):
            print(f"\n[+] Flag: {plaintext} que se corresponde con la llave: {key} y la palabra: {word}")
```

#### Flag
`crypto{k3y5__r__n07__p455w0rdz?}`

## Block Ciphers

### ECB CBC WTF

Here you can encrypt in CBC but only decrypt in ECB. That shouldn't be a weakness because they're different modes... right?

![Image](https://aes.cryptohack.org/static/img/aes/CBC_encryption.svg)

Play at https://aes.cryptohack.org/ecbcbcwtf

Original Code:

```py
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/ecbcbcwtf/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/ecbcbcwtf/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}
```

#### Solver

En este reto, sabemos que se está usando AES-128-CBC. Por tanto sabemos que el IV es de 16 bytes y que cada bloque dentro del cifrado es de 16 bytes. (32 en hexadecimal)

Al llamar a `encrypt_flag()` el programa nos arroja una cadena en hexadecimal formada por $$ ciphertext = iv.hex() + encrypted.hex() $$

Como sabemos la longitud de cada apartado, debemos de diseccionar los elementos para revertir el cifrado, para ello:

1. Recuperamos el IV original mediante ciphertext[:32]
2. Recuperamos el Ciphertext completo mediante ciphertext[32:0] siendo 64 longitud en hex.
3. Diseccionamos los bloques cifrados sabiendo que cada bloque son 32 longitud en hex ct_blocks = [ciphertext[:32], ciphertext[32:]]

Una vez tenemos toda la información diseccionada deberemos de revertir el cifrado.

![Decrypt](https://www.google.com/url?sa=i&url=https%3A%2F%2Fzhangzeyu2001.medium.com%2Fattacking-cbc-mode-bit-flipping-7e0a1c185511&psig=AOvVaw2b32V4uv1Z78ASWxDJOcW2&ust=1744312238444000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCJCEnc3Ty4wDFQAAAAAdAAAAABAE)

En este caso sabemos que solo tenemos dos bloques, `c0` y `c1`. Además tenemos la posiblidad de descifrar un bloque cifrado, por tanto podemos jugar con ello de la siguiente forma.

Sabemos que para obtener p1, el descifrado de C1 es de la forma $$ C_0 \oplus p_1 = decrypt(C_1) $$
Además si queremos obtenr p0, sabemos que el descifrado de C0 es de la forma $$ p_0 \oplus IV = decrypt(C_0) $$

Por tanto ya solo nos quedaría despejar `p0` y `p1` mediante `Xor` de la siguiente forma:

$$ p_0 = IV \oplus decrypt(C_0) $$
$$ p_1 = C_0 \oplus decypt(C_1) $$

Podemos hacerlo manualmente desde la página o en python.

```py
# Script SemiManual con explicacion
from Crypto.Cipher import AES

ct_data = "af6ac567810a710415ba4b66c8048724a86a7f3054649a68d14200ed204fdb91d08835f8705bfdc23ef5fb60a8fe4cb8"
iv = ct_data[:32]
ct = ct_data[32:]

ct_blocks = [ct[:32], ct[32:]]

print(f"\n[+] 1. Obtenemos la data iv + flag cifrada: {ct_data}")
print(f"\n[+] 2. Diseccionamos la información...")
print(f"\n[+] c0: {ct_blocks[0]}")
print(f"[+] c1: {ct_blocks[1]}")
print(f"[+] IV: {iv}") 

print(f"\n[+] 3. Mandamos a desencriptar C1...")
print(f"[+] 4. Realizamos XOR de decrypt(C1) ^ C0")
print(f"[+] 5. Convertimos la cadena resultante en bytes para leer en texto claro P1")

print(f"\n[+] 6. Mandamos a desencriptar C0...")
print(f"[+] 7. Realizamos XOR de decrypt(C0) ^ IV")
print(f"[+] 8. Convertimos la cadena resultante en bytes para leer en texto claro P0")

print(f"\n[+] 9. Concatenamos p0 || p1 para obtener finalmente la flag y LISTO!!")
```

```py
# Script de Ejemplo para la conexión
import requests

def strxor(a, b):     
    if len(a) > len(b):
       return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
       return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def get_flag_enc():
	r = requests.get(url+'ecbcbcwtf/encrypt_flag/')
	a = r.json()
	iv = a['ciphertext'].decode('hex')[:16]
	ciphertext = a['ciphertext'].decode('hex')[16:]
	return iv, ciphertext

def get_plaintext_ecb(ciphertext):
	r = requests.get(url+'ecbcbcwtf/decrypt/'+ciphertext+'/')
	a = r.json()
	p_0 = a['plaintext'].decode('hex')[:16]
	p_1 = a['plaintext'].decode('hex')[16:]

	return p_0, p_1

url = 'http://aes.cryptohack.org/'

iv, cipher = get_flag_enc()
c_hex = cipher.encode('hex')
p_0, p_1 = get_plaintext_ecb(c_hex)

actual1 = strxor(iv, p_0)
actual2 = strxor(cipher[:16], p_1)

print actual1+actual2
print p_1.encode('hex')
```

#### Flag
`crypto{3cb_5uck5_4v01d_17_!!!!!}`

### ECB Oracle

ECB is the most simple mode, with each plaintext block encrypted entirely independently. In this case, your input is prepended to the secret flag and encrypted and that's it. We don't even provide a decrypt function. Perhaps you don't need a padding oracle when you have an "ECB oracle"?

Play at https://aes.cryptohack.org/ecb_oracle

Original Code:

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


KEY = ?
FLAG = ?


@chal.route('/ecb_oracle/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}

    return {"ciphertext": encrypted.hex()}
```
#### Solver

Fuente [importante.](https://www.ctfrecipes.com/cryptography/symmetric-cryptography/aes/mode-of-operation/ecb/ecb-oracle)

Un vídeo dice más que mil palabras. [Video explicativo](https://www.youtube.com/watch?v=SLeTFY40PZQ)

```py
# Extraer los últimos 16bytes de la flag.
# Script de Ejemplo para la conexión
import requests

def get_request(param):

    URL = 'https://aes.cryptohack.org/ecb_oracle/'
    r = requests.get(URL +'encrypt/'+param+'/')
    response = r.json()
    return response["ciphertext"]

# Lista desde 01 hasta ff
byte_list = []
for i in range(1, 256):
    b = hex(i)[2:]
    if len(b) == 1:
        b = '0'+ b

    byte_list.append(b)

def get_padding(length):
    return byte_list[length - 1]


offset = 'AA' * 7
payload = offset
pad_count = 15
flag = ''
blank_block = '3150f4d79d7cc6c1d4b574b1fce84247' # Lo obtenemos mandando 'AA' * 7

while len(flag) < 32:

    payload +=  'AA'
    ciphertext = get_request(payload)
    last_block = ciphertext[-32:]

    if last_block == blank_block:
        last_block = ciphertext[-64:-32]
        pad_count = 16

    # Comparamos el primer block con el target
    for b in byte_list:

        inp = b + flag + get_padding(pad_count) * pad_count
        result = get_request(inp)

        print(f"[+] Probando con {inp}")
        frist_block = result[:32]

        if frist_block == last_block:
            print(f"\n[!] Encontrado {b}")
            flag = b + flag
            break

    pad_count -=  1

print(f"\n[+] Flag: {bytes.fromhex(flag)}")   

```

Una vez obtenidos los 16 últimos bytes de la flag, tenemos que modificar el script para dar paso a los siguientes 16 bytes.

```py
# Script de Ejemplo para la conexión
import requests

def get_request(param):

    URL = 'https://aes.cryptohack.org/ecb_oracle/'
    r = requests.get(URL +'encrypt/'+param+'/')
    response = r.json()
    return response["ciphertext"]

# Lista desde 01 hasta ff
byte_list = []
for i in range(1, 256):
    b = hex(i)[2:]
    if len(b) == 1:
        b = '0'+ b

    byte_list.append(b)

def get_padding(length):
    return byte_list[length - 1]


offset = 'AA' * 7 + 'AA' * 16
payload = offset
pad_count = 15
flag = '6e3675316e355f683437335f3363627d'
blank_block = '3150f4d79d7cc6c1d4b574b1fce84247' # Lo obtenemos mandando 'AA' * 7

while len(flag) < 32 + 18:

    payload +=  'AA'
    ciphertext = get_request(payload)
    last_block = ciphertext[-64:-32]

    if last_block == blank_block:
        last_block = ciphertext[-64:-32]
        pad_count = 16

    # Comparamos el primer block con el target
    for b in byte_list:

        inp = b + flag + get_padding(pad_count) * pad_count
        result = get_request(inp)

        print(f"[+] Probando con {inp}")
        frist_block = result[:32]

        if frist_block == last_block:
            print(f"\n[!] Encontrado {b}")
            flag = b + flag
            break

    pad_count -=  1

print(f"\n[+] Flag: {bytes.fromhex(flag)}")   
```
#### Solver
`crypto{p3n6u1n5_h473_3cb}`

### Flipping Cookie

You can get a cookie for my website, but it won't help you read the flag... I think.

Play at https://aes.cryptohack.org/flipping_cookie

#### Solver

En este reto nos dan una cookie y nos dan una función que comprueba si la cookie es de administrador o no. En caso de que `admin=True`, el servidor nos dará la flag.

Lo que tenemos que realizar es un bitflipping attack del valor de la cookie para cambiar `False` por `True`

La función `get_cookie()` nos da el `Iv` en los primeros 16 bytes y posteriormente el ciphertext concatenado.

```py
def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    cookie = f"admin=False;expiry={expires_at}".encode()

    iv = os.urandom(16)
    padded = pad(cookie, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()

    return {"cookie": ciphertext}
```

La función `check_admin()` toma como valores el `ciphertext` y el `Iv` y devuleve la flag si `admin=True`

```py
def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}

    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}
```
![cbc](https://aes.cryptohack.org/static/img/aes/CBC_decryption.svg)

Para el cifrado y el descifrado se utiliza `AES-CBC`. Por tanto sabemos que: 

$$ p_1 = c_0 \oplus d(c_1) $$
$$ d(c_1) = p_1 \oplus c_0 $$

Además, para hacer creer al servidor que somos admins, necesitamos flippear el ciphertext y el `IV`, ya que como podemos establecer nuestro propio `Iv`, podemos establecer relaciones Con Xor que nos permitan introducir un texto en claro que nosotros queramos. De esta manera el texto desencriptado contendrá "admin=True". Por tanto podemos estipular que:

$$ p_1' = c_0' \oplus d(c_1) $$
$$ p_1' = c_0' \oplus p_1 \oplus c_0 $$

Posteriormente, tenemos que establecer relaciones entre el Iv verdadero y el Iv falso a cambiar. Siendo `fake` el mensaje que el servidor debe leer, `plain` el mensaje original y `cipher` el texto cifrado que devuelve el servidor, podemos establecer:

$$ plain = cipher \oplus iv $$
$$ cipher = plain \oplus iv $$
$$ fake = cipher \oplus iv' $$
$$ iv' = fake \oplus cipher $$
$$ iv' = fake \oplus plain \oplus iv $$

Una vez se haya desencriptado nuestro texto cifrado malicioso, el servidor buscará la cadena que contenga "admin=True", por ende el mensaje que tenemos que falsear serà `;admin=True` por ende la parte que tenemos que cambiar será `admin=False` que se encuentra en el primer bloque.

Hay que recalcar, que el segundo bloque del texto en claro original, contiene la variable `expiry_at` la cual es diferente en cada cookie generada por tanto tenemos que establecer un texto en claro con la variable `expiry_at` al mismo momento, para guardar exactamente el valor que contiene, si no podremos tener problemas de padding.

El código final es el siguiente.

```py
# Script de Ejemplo para la conexión
import requests

from Crypto.Cipher import AES
import os
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
from pwn import xor

def get_cookie():

    URL = 'https://aes.cryptohack.org/flipping_cookie/get_cookie/'
    r = requests.get(URL)
    response = r.json()
    return response["cookie"]

def check_admin(cookie, iv):

    URL = 'https://aes.cryptohack.org/flipping_cookie/check_admin/'
    r = requests.get(URL+cookie+'/'+iv+'/')
    response = r.json()
    return response

def flip(cookie, plain):

    start = plain.find(b'admin=False')
    cookie = bytes.fromhex(cookie)

    # Nos creamos un iv'
    iv = [0x00]*16

    # Convierte los bytes a una lista de enteros
    cipher_fake = list(cookie)

    fake = b';admin=True;'

    for i in range(len(fake)):

        cipher_fake[16+i] = plain[16+i] ^ cookie[16+i] ^ fake[i] # Se utiliza 16 + i por que los 16 primeros son del IV original (No diseccionado)
        iv[start+i] = plain[start+i] ^ cookie[start+i] ^ fake[i]

    cipher_fake = bytes(cipher_fake).hex()
    iv = bytes(iv).hex()

    return cipher_fake, iv

# Obtenemos el valor de datatime acorde con el servidor.
expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
plain = f"admin=False;expiry={expires_at}".encode()

cookie = get_cookie()

cookie, iv = flip(cookie, plain)
print(check_admin(cookie, iv))
```

NOTA

Es importante conocer que:

$$ cipher_fake[16+i] = plain[16+i] \oplus cookie[16+i] \oplus fake[i] $$

Se utiliza para calcular el byte que se debe insertar en la posición correspondiente del bloque anterior (en el ciphertext) de modo que, al ser descifrado, la XOR con D(C) produzca el valor deseado fake[i]. De igual modo, la modificación en el IV:

$$ iv[start+i] = plain[start+i] \oplus cookie[start+i] \oplus fake[i] $$

Permite hacer lo mismo para el primer bloque. La aplicación del XOR en esta fórmula se basa en la propiedad involutiva del XOR (aplicar XOR dos veces con el mismo valor "deshace" la operación), lo que permite calcular la diferencia (la "delta") entre el valor original y el deseado, y luego "inyectar" esa diferencia en el vector que se XORará durante el descifrado.

Esta técnica es el núcleo del ataque de bitflipping en modo CBC: no es necesario conocer la clave para modificar el mensaje descifrado de manera controlada, sino que basta con conocer o inferir el texto plano original y luego aplicar la diferencia necesaria en el vector de XOR (ya sea el IV o el bloque cifrado previo).

#### Flag
`crypto{4u7h3n71c4710n_15_3553n714l}'`

### Lazy CBC

I'm just a lazy dev and want my CBC encryption to work. What's all this talk about initialisations vectors? Doesn't sound important.

Play at https://aes.cryptohack.org/lazy_cbc

#### Solver

En este reto podemos observar como la `key` se utiliza tanto como `iv` como en la propia `key` del cifrado y descifrado en `AES-CBC`

![cbc](https://aes.cryptohack.org/static/img/aes/CBC_decryption.svg)

Como estamos en `AES-CBC` podemos establecer las siguientes ecuaciones.

$$ key = iv = d(c_0) \oplus plaintext $$
$$ p_0 = d(c_0) \oplus iv $$
$$ p_1 = d(c_1) \oplus C_0 $$
$$ p_2 = d(c_2) \oplus C_1 $$

Si por ejemplo $$ c_1 = 0 $$ y $$ c_2 = c_0 $$ entonces tenemos las siguientes ecuaciones.

$$ p_0 = d(c_0) \oplus iv $$
$$ p_1 = d(0) \oplus C_0 $$
$$ p_2 = d(c_0) \oplus C_1 $$

Si además realizamos $$ p_0 \oplus p_2 $$ si la `key` es utilizada como `IV` entonces podemos realizar transformaciones para obtener el valor de `key`

$$ p_0 \oplus p_2 = d(c_0) \oplus iv \oplus d(c_0) \oplus 0 $$
$$ p_0 \oplus p_2 = d(c_0) \oplus iv \oplus d(c_0) $$

Podemos simplificar $$ d(c_0) \oplus d(c_0) = 0 $$ Por propiedades de `Xor`
Y por último, podemos simplificar un paso más con $$ iv \oplus 0 = iv $$

Por ende, la ecuación resultante es la siguiente:

$$ p_0 \oplus p_2 = iv $$

La cual podemos reescribir en factor de `key`:
$$ p_0 \oplus p_2 = key $$

Por ende, la metodología a realizar será la siguiente:

1. Ciframos la cadena $$ plaintext = b'a'*16*3 $$
2. Obtenemos el resultado cifrado y separamos en bloques de 16 bytes,
3. Creamos un texto cifrado falso de la siguiente forma.
$$ fake_cipher = cipher[:32] + '0'*32 + cipher[:32] $$
4. Desciframos la cadena haciendo uso de la función `receive()` y guardamos el resultado,
5. Separamos el texto en claro obtenido en bloques de 16 bytes,
6. Por último, realizamos `XOR` entre `p0` y `p2` para obtener la flag.

El código completo es el siguiente.

```py
from pwn import xor
import requests

URL = 'https://aes.cryptohack.org/lazy_cbc/'

def receive(ciphertext):
    r = requests.get(URL +'receive/'+ciphertext+'/')
    a = r.json()
    decrypted = a['error'][19:]
    return decrypted

def get_flag(key):
    r = requests.get(URL +'get_flag/'+key+'/')
    a = r.json()
    flag = a['plaintext']
    return flag

def encrypt(plaintext):

    r = requests.get(URL +'encrypt/'+plaintext+'/')
    a = r.json()
    ciphertext = a['ciphertext']
    return ciphertext

# 1. Creamos el texto en claro a cifrar y lo mandamos
plaintext = b'a'*16 * 3
cipher = encrypt(plaintext.hex())

# 2. Nos construimos nuestro mensaje cifrado falso
fake_cipher = cipher[:32] + '0'*32 + cipher[:32]
plaintext = receive(fake_cipher)

# 3. Estructuramos el mensaje en claro por bloques
plain_blocks = [plaintext[:32], plaintext[32:64], plaintext[64:]]  

# 4. Realizamos XOR entre el p0 y p2
key = xor(bytes.fromhex(plain_blocks[0]), bytes.fromhex(plain_blocks[2]))

flag_hex = get_flag(key.hex())
print(f"\n[+] Flag: {bytes.fromhex(flag_hex)}")
```

#### Flag
`crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}`

### Triple DES

Data Encryption Standard was the forerunner to AES, and is still widely used in some slow-moving areas like the Payment Card Industry. This challenge demonstrates a strange weakness of DES which a secure block cipher should not have.

Play at https://aes.cryptohack.org/triple_des

Challenge contributed by randomdude999

#### Solver

En este reto, podemos manipular las `keys` que se utilizan en el cifrado `TripleDes`.
Por ello, podemos establecer una clave que sea débil y aprovecharnos de ello.

¿Cómo sabemos que una clave en `DES` es débil?

Se dice que una clave en `DES` es débil si genera todas (o la mayoría) de las subclaves idénticas, la función de cifrado se vuelve casi simétrica. Esto significa que aplicar el algoritmo de cifrado sobre el mensaje cifrado con dicha clave puede revertir el proceso, es decir, la encriptación se vuelve su propia desencriptación. En esencia, si se tiene un mensaje $$ C = E_key(P) usando una clave débil, entonces $$ P = E_key(C) $$, lo que debilita grandemente la seguridad.

Además la falta de variabilidad en las subclaves reduce la complejidad interna del cifrado, por lo que ciertas técnicas de criptoanálisis pueden aprovechar esa estructura para descifrar mensajes cifrados o para encontrar la clave con menor esfuerzo.

Existen exactamente 4 claves débiles conocidas para DES y además unas 6 parejas de claves semi-débiles (12 claves en total) que presentan propiedades relacionadas. Con una clave débil, el proceso de generación de subclaves produce el mismo valor en cada ronda. Algunos ejemplos de claves débiles en DES (representadas en hexadecimal) son:

    Claves débiles:
    0101010101010101
    fefefefefefefefe
    e0e0e0e0f1f1f1f1
    1f1f1f1f0e0e0e0e

    Claves semidébiles:
    01fe01fe01fe01fe
    fe01fe01fe01fe01
    1fe01fe00ef10ef1
    e01fe01ff10ef10e
    01e001e001f101f1
    e001e001f101f101
    1ffe1ffe0e0efefe
    fe1ffe1ffe0e0efe
    011f011f010e010e
    1f011f010e010e01
    e0f1e0f1f1f0e0f1
    f1e0f1e0e0f1e0f1

En este caso el código aportado hace el siguiente procedimiento.

1. Se aplica un XOR con un IV (valor fijo para la sesión) al plaintext.

2. Se cifra el resultado con DES3 en modo ECB, usando la clave proporcionada.

3. Se vuelve a aplicar un XOR con el mismo IV al resultado.

Para el caso de dos claves, DES3 en PyCryptodome se interpreta como un esquema de dos claves, donde la clave proporcionada de 16 bytes se divide en dos partes:

$$ K_1 = primeros 8 bytes $$
$$ K_2 = segundos 8 bytes $$

El proceso de triple DES en modo de dos claves es el siguiente.

$$ C = E_K(D_k2(E_k1(M))) $$

Si elegimos un `K1` y un `K2` de forma en que ambos sean complementario uno de otro, se puede aprovechar la propiedad de complementariedad de DES. Esta propiedad cumple que:

$$ E(\overline{K},\, \overline{M}) = \overline{E(K, M)} $$

Por tanto, podemos decir que $$ K_2 = \overline{K_1} $$

Por lo que esto conduce a que en el esquema de dos claves de triple DES, la operación de cifrado se "deshaga" al aplicarla dos veces sobre el mismo mensaje. Por ende la función de cifrado haría lo siguiente:

$$ E(\overline{K},\, \overline{M}) = \overline{E(K, M)} $$

Por tanto, una clave que cumple estas propiedades es: 

    b'\x00\x00\x00\x00\x00\x00\x00\x00\x0cf\x0cf\x0cf\x0cf\x0cf\x0cf\x0cf\x0cf'

El código utilizado es el siguiente.

```py
from pwn import xor
import requests

URL = 'https://aes.cryptohack.org/triple_des/'

def xor(a, b):
    # xor 2 bytestrings, repeating the 2nd one if necessary
    return bytes(x ^ y for x,y in zip(a, b * (1 + len(a) // len(b))))

def receive(ciphertext):
    r = requests.get(URL +'receive/'+ciphertext+'/')
    a = r.json()
    decrypted = a['error'][19:]
    return decrypted

def encrypt(key, plaintext):
    r = requests.get(URL +'encrypt/'+key+'/'+plaintext+'/')
    a = r.json()
    cipher = a['ciphertext']
    return cipher

def encrypt_flag(key):
    r = requests.get(URL +'encrypt_flag/'+key+'/')
    a = r.json()
    encrypted_flag = a['ciphertext']
    return encrypted_flag

key = b'\x00'*8 + b'\xff'*8
print(key)
encrypt_flag = encrypt_flag(key.hex())

flag = encrypt(key.hex(), encrypt_flag)
print(f"\n[+] Flag: {bytes.fromhex(flag)}")
```

#### Flag
`crypto{n0t_4ll_k3ys_4r3_g00d_k3ys}`

## Stream Ciphers

### Symmetry
### Bean Counter
### CTRIME
### Logon Zero
### Stream of Consciousness
### Dancing Queen
### Oh SNAP

## Padding Attacks

### Pad Thai
### The Good, The Pad, The Ugly
### Oracular Spectacular

## Authenticated Encryption

### Paper Plane
### Forbidden Fruit

## Linear CryptAnalysis
### Beatboxer