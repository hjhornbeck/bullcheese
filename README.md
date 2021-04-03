# BullCheese
A trusted third party for Minecraft Filtered Seed Glitchless speedrunning.

## Introduction

Filtered Seed Glitchless is intended as a middle ground between two other speedrunning categories. Random Seed Glitchless speedrunning is chaotic and exciting to watch, but it also involves a lot of resets and failed attempts. Set Seed Glitchless has far fewer resets and a more obvious skill progression, but running the same seed over and over gets boring quickly. Enter FSG: you don't know which seed you'll be running, but you know that seed has been filtered to be more viable than average. It's more exciting for viewers and runners alike than either RSG or SSG.

The tricky part of FSG is the implementation. You can't allow runners to pick their own seed, as then FSG is no different than SSG. You can't have human beings dealing out seeds, as that's both impractical given the size of the Minecraft speedrunning community and ripe for abuse. And yet you still need some sort of verification framework in place to be a valid speedrun.

BullCheese is a solution to the implementation puzzle. It is a simple [Flask](https://flask.palletsprojects.com/en/1.1.x/) application for handing out FSG seed "tickets", that give the holder a limited window to attempt a FSG run. If the runner desires to validate their run, they hand the seed they ran, the ticket they were given, and the server they got both from to a validator. The validator is able to use BullCheese to verify the seed was assigned by the server and the run was performed within a specific time window after it was assigned, with a high degree of confidence, and thus verify the runner was not practicing on that seed.

It is designed to be quite flexible, as well. The server manager can tweak the size of the ticket, change how long the ticket is "live" for, and raise or lower the security of tickets. It can be easily adapted for tournaments, with custom seed pools swapped for the default ones. Validators can be permitted to verify tickets offline, without needing access to the server itself. The code is released under a [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) license, so it can be forked and modified. Launching the server has been made as simple as possible, with secure defaults, so you can set up your own server with a few clicks.

## How it Works

The code to generate and verify tickets is executed on a third-party server, so that it can only be modified by an administrator of that server. While all the source code and even the seeds are public, two security tokens are kept private: the private key and the salt. 

Seeds are organized into categories, which have a number, URL, and long name. The number is an arbitrary value between 0 and 225, inclusive. The URL is the URL these seeds can be accessed from via the web interface, while the long name is the text name presented to the player. These last two are burned into the seed file itself, while the number is set by the filename.

The lifespan of a ticket is divided into three periods: *live*, *dead*, and *invalid/expired*. While it is *live*, the associated seed can be speedrun. A *dead* ticket can no longer result in a valid speedrun, but if validated it can still be verified by anyone. At all other times, the ticket cannot be run or verified and it is considered no different than random garbage pretending to be a ticket. The default live period is two hours after the ticket was generated, and the default dead period is two weeks after generation, but these values can be changed.

When asked to generate a ticket, the code picks a random seed from a list and calculates the following value:

```
Encrypt( KEY, seed, category, time,  Truncate(HMAC( SALT, seed, category, time )) )
```

`KEY` is the private key and `SALT` the salt, obviously. `seed` is the chosen Minecraft seed, as eight bytes. `category` is the numeric category the seed was chosen from, and one byte long. `time` is the time the ticket was created, but encoded in a special format. It is common to store times as the number of seconds since an "epoch" or reference time, typically January 1st 1970, but here the epoch is instead January 1st, 2021. The unit of time is not seconds, but eighths of a second; the choice of unit controls how often tickets are generated (no two tickets can have the same time) and effects the security, and this unit was thought to be a good compromise. The time occupies four bytes.

`HMAC` is short for "[keyed-Hash Message Authentication Code](https://en.wikipedia.org/wiki/HMAC)". It is a function that takes an arbitrary number of bytes plus a key, and converts both to a code of fixed length. In this case we use [SHA2-256](https://en.wikipedia.org/wiki/SHA-2), so the resulting code is 32 bytes long, and use the salt as the key. This code is cryptographically secure: no-one has found a way to use this code to learn anything about the original bytes given to the function. Without knowing the input and salt, it appears no different than a random number.

`Truncate` is a function that discards the last bytes of the HMAC code. How many bytes are discarded depends on the size of the ticket: a two-block ticket (the default) discards the last thirteen bytes, so the entire length of the ticket is two 16-byte blocks long, while a one-block ticket discards the last twenty-nine bytes. The net result is exactly sixteen bytes long for a one-block ticket, after prepending the seed, category number, and time.

`Encrypt` is a function that takes an input and a key, and creates an encrypted version of the input known as a "cyphertext." Here we use [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), a cryptographically-secure algorithm, in [electronic code book](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB) mode to encrypt the ticket. There is no efficient way to decrypt the ticket without knowing the key in advance; your best alternative is to try every possible key, which even at the lowest security settings would require billions of years and every known computer to acheive. At the highest security setting, it is considered safe against quantum computation.

This value is converted to a hexadecimal number. Dashes are inserted at specific places, both to make the ticket easier for humans to read but also to specify the version of the system used. The final result is a "ticket."

Verification is done by reversing this process. Dashes are verified to be in the proper place, stripped out, and the hexadecimal number converted to a byte sequence. This sequence is decrypted with the private key, (hopefully) revealing the Minecraft seed, category, and ticket creation time. If the salt is known, the HMAC is calculated and verified to match what was included inside the ticket. Additional checks are done: does the provided seed match the one in the ticket? Does that category contain the seed? And which of the three periods does the creation time fall into?

## Security

## Parameters

## .... "BullCheese?"
