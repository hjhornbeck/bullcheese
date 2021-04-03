# BullCheese
A trusted third party for Minecraft Filtered Seed Glitchless speedrunning.

## Introduction

Filtered Seed Glitchless is intended as a middle ground between two other speedrunning categories. Random Seed Glitchless speedrunning is chaotic and exciting to watch, but it also involves a lot of resets and failed attempts. Set Seed Glitchless has far fewer resets and a more obvious skill progression, but running the same seed over and over gets boring quickly. Enter FSG: you don't know which seed you'll be running, but you know that seed has been filtered to be more viable than average. It's more exciting for viewers and runners alike than either RSG or SSG.

The tricky part of FSG is the implementation. You can't allow runners to pick their own seed, as then FSG is no different than SSG. You can't have human beings dealing out seeds, as that's both impractical given the size of the Minecraft speedrunning community and ripe for abuse. And yet you still need some sort of verification framework in place to be a valid speedrun.

BullCheese is a solution to the implementation puzzle. It is a simple [Flask](https://flask.palletsprojects.com/en/1.1.x/) application for handing out FSG seed "tickets", that give the holder a limited window to attempt a FSG run. If the runner desires to validate their run, they hand the seed they ran, the ticket they were given, and the server they got both from to a validator. The validator is able to use BullCheese to verify the seed was assigned by the server and the run was performed within a specific time window after it was assigned, with a high degree of confidence, and thus verify the runner was not practicing on that seed.

It is designed to be quite flexible, as well. The server manager can tweak the size of the ticket, change how long the ticket is "live" for, and raise or lower the security of tickets. It can be easily adapted for tournaments, with custom seed pools swapped for the default ones. Validators can be permitted to verify tickets offline, without needing access to the server itself. The code is released under a [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) license, so it can be forked and modified. Launching the server has been made as simple as possible, with secure defaults, so you can set up your own server with a few clicks.

## How it Works

## Security

## Parameters

## .... "BullCheese?"
