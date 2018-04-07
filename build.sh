#!/bin/sh
rm -rf CMakeFiles/ CMakeCache.txt

# Enable HWLOC library support? Defaults to ON
hwloc="ON"

# Enable webserver support? Defaults to ON
microhttpd="ON"

# Enable CUDA GPU support? Defaults to ON
cuda="ON"

# Enable OpenCL GPU support? Defaults to ON
opencl="ON"

# Verbose compilation? Defaults to OFF
verbose="OFF"

#
# What is the oldest cpu the compiled binary needs to work with?
# Choose "native" if you only need to support the local machine.
# If you need to support other computers, choosing an older cpu is safer.
# Supported parameters depend on your gcc version.
# See: https://gcc.gnu.org/onlinedocs/gcc-6.4.0/gcc/x86-Options.html
#
## Default to native ##
arch=native

## AMD cpus ##
#arch="athlon64"
#arch="athlon64-sse3"
#arch="barcelona"
#arch="bdver1"
#arch="bdver2"
#arch="bdver3"
#arch="bdver4"
#arch="znver1"
#arch="btver1"
#arch="btver2"

## Intel cpus ##
#arch="pentium4"
#arch="prescott"
#arch="core2"
#arch="nehalem"
#arch="westmere"
#arch="sandybridge"
#arch="ivybridge"
#arch="haswell"
#arch="broadwell"
#arch="skylake"
#arch="bonnell"
#arch="silvermont"
#arch="knl"
#arch="skylake-avx512"


# Enable static linking if arch is not native
static="OFF"
if [ "$arch" == "native" ]
then
    static="ON"
fi

# Optionally override static linking here if needed
# static="OFF"



#########################
# Usually no need to change anything below this point
##########

set -x

cmake . -DCMAKE_VERBOSE_MAKEFILE="$verbose" -DCMAKE_LINK_STATIC="$static" -DARCH="$arch" -DHWLOC_ENABLE="$hwloc" -DMICROHTTPD_ENABLE="$microhttpd" -DCUDA_ENABLE="$cuda" -DOpenCL_ENABLE="$opencl"

make -j3
