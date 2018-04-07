#!/bin/sh

# Enable HWLOC library support? Defaults to ON
hwloc="ON"

# Enable webserver support? Defaults to ON
microhttpd="ON"

# Enable OpenSSL encryption support? Defaults to ON
openssl="ON"

# Enable CPU mining support? Defaults to ON
cpu="ON"

# Enable Nvidia CUDA GPU mining support? Defaults to ON
cuda="ON"

# Enable OpenCL mining support? Defaults to ON
opencl="ON"

# Enable GCC's LTO optimized compilation mode? Defaults to ON
lto="ON"

# Verbose compilation? Defaults to OFF
verbose="OFF"

# Install path
installprefix="/opt/CryptoGoblin/"

# Advanced cmake options, space delimited.
cmakeopt=""

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
if [ "$arch" != "native" ]
then
    static="ON"
fi

# Optionally override static linking here if needed
# static="OFF"






#########################
# Usually no need to change anything below this point
##########

rm -rf CMakeFiles/ CMakeCache.txt
mkdir -p build
cd build
rm -rf CMakeFiles/ CMakeCache.txt

set -x
cmake .. -L -DCMAKE_VERBOSE_MAKEFILE="$verbose" -DCMAKE_LINK_STATIC="$static" -DCMAKE_INSTALL_PREFIX="$installprefix" -DARCH="$arch" -DCG_LTO="$lto" -DHWLOC_ENABLE="$hwloc" -DMICROHTTPD_ENABLE="$microhttpd" -DOpenSSL_ENABLE="$openssl" -DCPU_ENABLE="$cpu" -DCUDA_ENABLE="$cuda" -DOpenCL_ENABLE="$opencl" $cmakeopt

make -j3
set +x

cd ..
echo "If compilation succeeded, you can now run 'make install', or run/copy the executable directly in/from the build/bin/ folder"
