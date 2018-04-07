# CryptoGoblin - CryptoNight CPU mining tool
** for coins based on cryptonight-classic, cryptonight-light or cryptonight-heavy.
** Support for Monero, Electroneum, Aeon, Sumokoin, Edollar and more.
CryptoGoblin is a greedy mining goblin that will push the cpu to get as many hashes as possible,
if you believe in cpu-rights, then this might not be the mining tool for you.

CryptoGoblin was forked from xmr-stak, but it utilizes several GCC compiler-specific tweaks and
many other (medium, small, minor and micro) optimizations to get the most speed out of your cpu.

Dev fee mining is set to 1.5%, and part of it goes to xmr-stak authors.

## Overview
* [Configuration](#configuration)
* [Download](https://github.com/Dead2/CryptoGoblin/releases)
* [CPU Tuning](doc/tuning-cpu.md)
* [GPU Tuning](doc/tuning-gpu.md)
* [Compilation](#compile)

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

## compile
Linux compilation using build.sh
This will build with LTO enabled, and some really aggressive optimization flags.

If you are lucky, this might give you anything from 0% to 60% improvement, if you are not lucky
it could be a couple percent slower. Soft-aes will see the really huge improvements.

To compile, run:
`./build.sh`

microhttpd server is disabled by default, since it has a small impact on the performance
and don't really bring much to the table. Just toggle it from OFF to ON in the bottom of
build.sh if you want to use it.

You can easily modify build.sh yourself to experiment with adding or removing flags.


## Linux compilation and dependencies
- GCC 6.0 or higher is recommended, but 5.1 should also work.
  (GCC 5.x will cause an error, but you can remove the erroring flag from build.sh)
- gcc-c++ version 5.1 or higher is required for full C++11 support.
- (Optional) openssl devel package for encrypted ssl pool connections.
- (Optional) libmicrohttpd devel package for running the integrated http server.
- (Optional) hwloc devel package for improved autoconf in dual and quad-cpu (not core) systems.

```bash
    # Ubuntu 17.04 GCC 7.x installation
    sudo add-apt-repository ppa:ubuntu-toolchain-r/test
    sudo apt-get update
    sudo apt-get install gcc-7 g++-7

    # Ubuntu / Debian
    sudo apt-get install libmicrohttpd-dev libssl-dev cmake build-essential libhwloc-dev
    build.sh

    # Fedora
    sudo dnf install gcc gcc-c++ hwloc-devel libmicrohttpd-devel openssl-devel cmake
    build.sh

    # CentOS
    sudo yum install centos-release-scl cmake3 hwloc-devel libmicrohttpd-devel openssl-devel
    sudo yum install devtoolset-7-gcc*
    scl enable devtoolset-7 bash
    build.sh

    make install (Or just copy/run the executable from the bin folder manually)
```


If you want to make a little donation directly to me (Dead2), transfers or donation mining (at pool.supportxmr.com:3333), my XMR address is:
```
45obtQLBPgyZL8Xb4qFFdZQLZugJzkHUo7oHeKd2zZSmfjxRg6WKhAjD4o1eb6LjK1RY2V4sp1nmDAity9Ks9NvZHw8z1EL
```
Any donation is much appreciated.

