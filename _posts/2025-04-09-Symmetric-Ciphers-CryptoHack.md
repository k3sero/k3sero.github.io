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

The most famous symmetric-key cipher is Advanced Encryption Standard (AES), standardised in 2001. It's so widespread that modern processors even contain special instruction sets to perform AES operations. The first series of challenges here guides you through the inner workings of AES, showing you how its separate components work together to make it a secure cipher. By the end you will have built your own code for doing AES decryption!

We can split symmetric-key ciphers into two types, block ciphers and stream ciphers. Block ciphers break up a plaintext into fixed-length blocks, and send each block through an encryption function together with a secret key. Stream ciphers meanwhile encrypt one byte of plaintext at a time, by XORing a pseudo-random keystream with the data. AES is a block cipher but can be turned into a stream cipher using modes of operation such as CTR.

Block ciphers only specify how to encrypt and decrypt individual blocks, and a mode of operation must be used to apply the cipher to longer messages. This is the point where real world implementations often fail spectacularly, since developers do not understand the subtle implications of using particular modes. The remainder of the challenges see you attacking common misuses of various modes.

## How AES Works

### Keyed Permutations
### Resisting Bruteforce
### Structure of AES
### Round Keys
### Confusion through Substitution
### Diffusion through Permutation
### Bringing It All Together


## Symmetric Starter

### Modes of Operation Starter
### Passwords as Keys

## Block Ciphers

### ECB CBC WTF
### ECB Oracle
### Flipping Cookie
### Lazy CBC
### Triple DES

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