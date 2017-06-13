# Fork of XMR-Stak-CPU - Monero mining software

Forked from https://github.com/fireice-uk/xmr-stak-cpu and the donation mining still goes to him.
If you want to donate to Dead2, my XMR address is 
```
45obtQLBPgyZL8Xb4qFFdZQLZugJzkHUo7oHeKd2zZSmfjxRg6WKhAjD4o1eb6LjK1RY2V4sp1nmDAity9Ks9NvZHw8z1EL
```

This fork makes LTO compilation possible, and contains a build script that compiles using
LTO and an insane collection of CFLAGS.

## build.sh
You should not use this unless you know what you are doing.
This might break things in so many ways.
Many/most of these flags should be pruned away, but that takes time.

I only post this due to popular demand, not because it is pretty,
safe, or even good settings for everyone. Besides, I'd really rather keep it to myself. :P

This will build with LTO enabled, and some really aggressive
optimization flags. BAD IDEA(TM)

If you are lucky, this might give you anything from 0% to 15%
improvement, if you are not lucky, it could give you -30% or even
crash randomly, who knows..

Are you sufficiently warned by now? I hope so :)

To use this, instead of running cmake directly, run:
./build.sh

GCC 6.0 or higher is recommended for this, but 5.1 might also work.
I also disable hwloc and the microhttpd server, since they have a small impact
on the performance. Just toggle them from OFF to ON in the bottom of build.sh if
you actually need them.

PS: I have yet to find a cpu that needs no-prefetch=true, so make sure you try with false.

## Linux compilation
### GNU Compiler
```
    # Ubuntu / Debian
    sudo apt-get install libmicrohttpd-dev libssl-dev cmake build-essential libhwloc-dev
    cmake .

    # Fedora
    sudo dnf install gcc gcc-c++ hwloc-devel libmicrohttpd-devel openssl-devel cmake
    cmake .

    # CentOS
    sudo yum install centos-release-scl cmake3 hwloc-devel libmicrohttpd-devel openssl-devel
    sudo yum install devtoolset-4-gcc*
    sudo scl enable devtoolset-4 bash
    cmake3 .

    make install
```

- GCC version 5.1 or higher is required for full C++11 support. CMake release compile scripts, as well as CodeBlocks build environment for debug builds is included.

### To do a static build for a system without gcc 5.1+
```
    cmake -DCMAKE_LINK_STATIC=ON .
    make install
```
Note - cmake caches variables, so if you want to do a dynamic build later you need to specify '-DCMAKE_LINK_STATIC=OFF'


You can find the complete README file at https://github.com/fireice-uk/xmr-stak-cpu
