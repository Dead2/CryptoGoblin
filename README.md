# XMR-Stak-CPU-Dead2 - Monero CPU mining tool
Forked from https://github.com/fireice-uk/xmr-stak-cpu and part of the donation mining still goes to them.

If you want to make a little donation directly to me (Dead2), transfers or donation mining (at pool.supportxmr.com:5555), my XMR address is:
```
45obtQLBPgyZL8Xb4qFFdZQLZugJzkHUo7oHeKd2zZSmfjxRg6WKhAjD4o1eb6LjK1RY2V4sp1nmDAity9Ks9NvZHw8z1EL
```
Any donation is much appreciated.

## Description
This fork of xmr-stak-cpu makes LTO compilation possible, and contains a build script that compiles
using LTO and a collection of CFLAGS that might provide you with a benefit.
In addition, several tweaks and improvements have been implemented.

## Configuration
Run the miner with the default config file unchanged, and it will suggest a thread config for you.
Each thread needs 2MB cache.
**Do NOT run more threads than you have cache for, even if you have free cores.**
Tune by adding threads until it slows down, then back off.

If you use a release compiled using Microsoft Visual Studio, then no-prefetch should be set to "true".
If you use a release compiled using GCC, or a MinGW release, then no-prefetch should be set to "false".

After you have found your optimal config, try flipping ONE thread per cpu to the opposite of the rest,
this will pretty much make that thread the designated victim in a cache-starved situation. That thread
might now be slower, but the rest will be faster, so hopefully you gained a few H/s total.


## Linux compilation using build.sh
This will build with LTO enabled, and some really aggressive optimization flags.

If you are lucky, this might give you anything from 0% to 15% improvement,
if you are not lucky it could be a couple percent slower.

To use this, instead of running cmake directly, run:
`./build.sh`

Hwloc and the microhttpd server is disabled by default, since they have a small impact
on the performance and don't really bring much to the table. Just toggle them from OFF to ON
in the bottom of build.sh if you actually need them.

You can easily modify build.sh yourself to experiment with adding or removing flags.

Most cpus like FLATTEN and FLATTEN2 enabled, and FLATTEN3 disabled, but you can experiment
with enabling/disabling these at will.

See below for compile requirements:

## Linux compilation and dependencies
- GCC 6.0 or higher is recommended, but 5.1 should also work.
- gcc-c++ version 5.1 or higher is required for full C++11 support.
- (Optional) openssl devel package for encrypted ssl pool connections.
- (Optional) libmicrohttpd devel package for running the integrated http server.
- (Optional) hwloc devel package for improved autoconf in dual and quad-cpu (not core) systems.

```bash
    # Ubuntu / Debian
    sudo apt-get install libmicrohttpd-dev libssl-dev cmake build-essential libhwloc-dev
    build.sh OR cmake .

    # Fedora
    sudo dnf install gcc gcc-c++ hwloc-devel libmicrohttpd-devel openssl-devel cmake
    build.sh OR cmake .

    # CentOS
    sudo yum install centos-release-scl cmake3 hwloc-devel libmicrohttpd-devel openssl-devel
    sudo yum install devtoolset-6-gcc*
    scl enable devtoolset-6 bash
    build.sh OR cmake3 .

    make install (Or just copy/run the executable from the bin folder manually)
```



## Windows compilation
- see [WINCOMPILE.md](WINCOMPILE.md)


You can find the complete README file at https://github.com/fireice-uk/xmr-stak-cpu
