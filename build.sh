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

# Make portable executable? This enables optimizations for cpus newer than "arch"
# and enables static compilation of libgcc and libstdc++. Defaults to OFF
# Not needed when using "arch=native" and using the executable on the local machine
portable="OFF"

# Optionally force enable/disable static build by uncommenting:
# static="ON"

# Disable all algorithms except the one needed by Monero/XMR. This results
# in a smaller executable and can give a tiny speedup. Defaults to OFF
# This will make the miner unable to work properly for any other algorithm.
onlyxmr="OFF"

# What is the oldest cpu the compiled binary needs to work with?
# Choose "native" if you only need to support the local machine.
# If you need to support other computers, choosing an older cpu is safer.
# Supported parameters depend on your gcc version.
# See: https://gcc.gnu.org/onlinedocs/gcc-6.4.0/gcc/x86-Options.html

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
#arch="nocona"
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








#########################
# Usually no need to change anything below this point
##########

# Enable static linking if portable is enabled
if [ -z "$static" ]
then
  static="OFF"
  if [ "$portable" == "ON" ]
  then
    static="ON"
  fi
fi

rm -rf CMakeFiles/ CMakeCache.txt
mkdir -p build
cd build
rm -rf CMakeFiles/ CMakeCache.txt

set -x
cmake .. -L -DCMAKE_VERBOSE_MAKEFILE="$verbose" -DCMAKE_LINK_STATIC="$static" -DCMAKE_INSTALL_PREFIX="$installprefix" -DARCH="$arch" -DCG_LTO="$lto" -DCG_PORTABLE="$portable" -DCG_ONLY_XMR="$onlyxmr" -DHWLOC_ENABLE="$hwloc" -DMICROHTTPD_ENABLE="$microhttpd" -DOpenSSL_ENABLE="$openssl" -DCPU_ENABLE="$cpu" -DCUDA_ENABLE="$cuda" -DOpenCL_ENABLE="$opencl" $cmakeopt

make -j3
set +x

strip --strip-all -R .comment build/bin/CryptoGoblin

cd ..
echo "If compilation succeeded, you can now run 'make install', or run/copy the executable directly in/from the build/bin/ folder"
