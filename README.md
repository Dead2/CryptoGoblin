# Fork of XMR-Stak-CPU - Monero mining software

Forked from https://github.com/fireice-uk/xmr-stak-cpu and part of the donation mining still goes to him.
If you want to donate directly to me (Dead2), my XMR address is 
```
45obtQLBPgyZL8Xb4qFFdZQLZugJzkHUo7oHeKd2zZSmfjxRg6WKhAjD4o1eb6LjK1RY2V4sp1nmDAity9Ks9NvZHw8z1EL
```

This fork makes LTO compilation possible, and contains a build script that compiles using
LTO and a collection of CFLAGS that might provide you with a benefit.

## HTML and JSON API report configuraton

To configure the reports shown above you need to edit the httpd_port variable. Then enable wifi on your phone and navigate to <miner ip address>:<httpd_port> in your phone browser. If you want to use the data in scripts, you can get the JSON version of the data at url <miner ip address>:<httpd_port>/api.json

## Usage on Windows 
1) Edit the config.txt file to enter your pool login and password. 
2) Double click the exe file. 


## build.sh
This will build with LTO enabled, and some really aggressive optimization flags.

If you are lucky, this might give you anything from 0% to 15% improvement,
if you are not lucky it could be a couple percent slower.

To use this, instead of running cmake directly, run:
./build.sh

GCC 6.0 or higher is recommended for this, but 5.1 might also work.
I also disable hwloc and the microhttpd server, since they have a small impact
on the performance. Just toggle them from OFF to ON in the bottom of build.sh if
you actually need them.

You can easily modify build.sh yourself to experiment with adding or removing flags.

Some cpus like FLATTEN and FLATTEN2 to be enabled, but a few old cpus seem to
do better with it disabled, so just comment out the flatten line before compiling
to test it yourself.

PS: I have yet to find a cpu that needs a no-prefetch=true config using my fork of the miner,
so make sure you try with false even if you normally would use true.

## Compile for Windows
- see [WINCOMPILE.md](WINCOMPILE.md)

## Linux compilation
### GNU Compiler
```
    # Ubuntu / Debian
    sudo apt-get install libmicrohttpd-dev libssl-dev cmake build-essential libhwloc-dev
    build.sh OR cmake .

    # Fedora
    sudo dnf install gcc gcc-c++ hwloc-devel libmicrohttpd-devel openssl-devel cmake
    build.sh OR cmake .

    # CentOS
    sudo yum install centos-release-scl cmake3 hwloc-devel libmicrohttpd-devel openssl-devel
    sudo yum install devtoolset-6-gcc*
    sudo scl enable devtoolset-6 bash
    build.sh OR cmake3 .

    make install (Or just copy/run the executable from the bin folder manually)
```

- g++ version 5.1 or higher is required for full C++11 support. CMake release compile scripts, as well as CodeBlocks build environment for debug builds is included.

### To do a static build for a system without gcc 5.1+
```
    cmake -DCMAKE_LINK_STATIC=ON .
    make install
```
Note - cmake caches variables, so if you want to do a dynamic build later you need to specify '-DCMAKE_LINK_STATIC=OFF'


You can find the complete README file at https://github.com/fireice-uk/xmr-stak-cpu
