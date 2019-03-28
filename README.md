# CryptoGoblin - CryptoNight CPU/GPU mining tool
**For coins based on the cryptonight algorithm family.**<br>
**Support for Monero, Electroneum, Aeon, Sumokoin, Edollar and many more.**

CryptoGoblin is a greedy mining goblin that will push the cpu to get as many hashes as possible,
if you believe in cpu-rights, then this might not be the mining tool for you.

## Overview
* [Download](https://github.com/Dead2/CryptoGoblin/releases)
* [Documentation](https://github.com/Dead2/CryptoGoblin/tree/master/doc)

CryptoGoblin was forked from xmr-stak in early 2017, it utilizes several GCC compiler-specific tweaks and
many other (medium, small, minor and micro) optimizations to get the most speed out of your cpu.<br>
CryptoGoblin can also be compiled using MSVC, but several of the optimizations will not be activated.

## Installation and Configuration
If you are using Windows, download the pre-compiled windows binaries, or compile them yourself.<br>
If you are using Linux, MacOS, BSD or similar, you need to compile them yourself.

After you have compiled or downloaded the executables, just run the miner without any configuration files,
and it will help you generate the config files. After that, you can optionally tune your configuration.
* [CPU Tuning](doc/tuning-cpu.md)
* [GPU Tuning](doc/tuning-gpu.md)

## Windows
Download the pre-compiled binaries [here](https://github.com/Dead2/CryptoGoblin/releases)

## Compilation
CryptoGoblin includes a script `build.sh` that can be edited to easily change important settings
and then run to start the compilation.

To compile, run:
`./build.sh`

For more information about compiling and dependencies, please have a look at the documentation
targeting your OS/distro [here](https://github.com/Dead2/CryptoGoblin/tree/master/doc).

## Donation
Dev fee mining is set to 1.4%, and part of it goes to xmr-stak authors.

If you want to make a little donation directly to me (Dead2), transfers or donation mining (at pool.supportxmr.com:3333), my XMR address is:
```
45obtQLBPgyZL8Xb4qFFdZQLZugJzkHUo7oHeKd2zZSmfjxRg6WKhAjD4o1eb6LjK1RY2V4sp1nmDAity9Ks9NvZHw8z1EL
```
Any donation is much appreciated.

