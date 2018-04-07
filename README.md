# CryptoGoblin - CryptoNight CPU mining tool
** for coins based on cryptonight-classic, cryptonight-light or cryptonight-heavy. **
** Support for Monero, Electroneum, Aeon, Sumokoin, Edollar and more. **
CryptoGoblin is a greedy mining goblin that will push the cpu to get as many hashes as possible,
if you believe in cpu-rights, then this might not be the mining tool for you.

CryptoGoblin was forked from xmr-stak in early 2017, it utilizes several GCC compiler-specific tweaks and
many other (medium, small, minor and micro) optimizations to get the most speed out of your cpu.
CryptoGoblin can also be compiled using, but several of the optimizations will not be activated.

Dev fee mining is set to 1.5%, and part of it goes to xmr-stak authors.

## Overview
* [Configuration](#configuration)
* [Download](https://github.com/Dead2/CryptoGoblin/releases)
* [CPU Tuning](doc/tuning-cpu.md)
* [GPU Tuning](doc/tuning-gpu.md)
* [Compilation](#compile)
* [Documentation](https://github.com/Dead2/CryptoGoblin/tree/master/doc)

## Configuration
Run the miner with the default config file unchanged, and it will suggest a thread config for you.
Each thread needs 2MB cache.
**Do NOT run more threads than you have cache for, even if you have free cores.**
Tune by adding threads until it slows down, then back off.

If you use a release compiled using GCC, or a MinGW release, then prefetch should be set to "true".
If you use a release compiled using Microsoft Visual Studio, then prefetch should be set to "false".

Detailed tuning information can be found in the TUNING.txt file

## Windows
Download the pre-compiled release here https://github.com/Dead2/CryptoGoblin/releases

## Compilation
CryptoGoblin includes a script `build.sh` that can be edited to easily change important settings
and then run to start the compilation.

To compile, run:
`./build.sh`

For more information about compiling and dependencies, please have a look at the documentation
targeting your OS/distro [here](https://github.com/Dead2/CryptoGoblin/tree/master/doc).

## Donation
If you want to make a little donation directly to me (Dead2), transfers or donation mining (at pool.supportxmr.com:3333), my XMR address is:
```
45obtQLBPgyZL8Xb4qFFdZQLZugJzkHUo7oHeKd2zZSmfjxRg6WKhAjD4o1eb6LjK1RY2V4sp1nmDAity9Ks9NvZHw8z1EL
```
Any donation is much appreciated.

