# Compile CryptoGoblin

## Content Overview
* [Build System](#build-system)
* [Generic Build Options](#generic-build-options)
* [CPU Build Options](#cpu-build-options)
* [AMD Build Options](#amd-build-options)
* [NVIDIA Build Options](#nvidia-build-options)
* [Compile on Windows](compile_Windows.md)
* [Compile on Linux](compile_Linux.md)
* [Compile on FreeBSD](compile_FreeBSD.md)
* [Compile on macOS](compile_macOS.md)

## Build System

The build system is CMake, but to make compiling more convenient, *CryptoGoblin* uses a wrapper script called 'build.sh'

By default the miner will be build with all dependencies. Each optional dependency can be disabled (this will reduce the miner features).

The easiest way to edit the configuration for *CryptoGoblin* is to edit build.sh before running it.

## Optional advanced compile options
Additional cmake-options can be specified in build.sh in the 'cmakeopt' setting.

After the configuration you need to compile the miner, follow the guide for your platform:
* [Compile in Windows](compile_Windows.md)
* [Compile in Linux](compile_Linux.md)
* [Compile in FreeBSD](compile_FreeBSD.md)
* [Compile in macOS](compile_macOS.md)

### Generic Build Options
- `MICROHTTPD_ENABLE` allow to disable/enable the dependency *microhttpd*
  - there is no *http* interface available if option is disabled
- `OpenSSL_ENABLE` allow to disable/enable the dependency *OpenSSL*
  - it is not possible to connect to a *https* secured pool if option is disabled

### CPU Build Options

- `CPU_ENABLE` allow to disable/enable the CPU backend of the miner
- `HWLOC_ENABLE` allow to disable/enable the dependency *hwloc*
  - disabling can reduce the miner performance on multi-cpu systems

### AMD Build Options

- `OpenCL_ENABLE` allow to disable/enable the AMD backend of the miner

### NVIDIA Build Options

- `CUDA_ENABLE` allow to disable/enable the NVIDIA backend of the miner
- `CUDA_ARCH` build for a certain compute architecture
  - this option needs a semicolon separated list
  - `cmakeopt="-DCUDA_ARCH=61"` or `cmakeopt="-DCUDA_ARCH=20;61"`
  - [list](https://developer.nvidia.com/cuda-gpus) with NVIDIA compute architectures
  - by default the miner is created for all currently available compute architectures
- `CUDA_COMPILER` select the compiler for the device code
  - valid options: `nvcc` or `clang` if clang 3.9+ is installed
  - The following sets host and device code to be compiled with clang
  - ´cmakeopt="-DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DCUDA_COMPILER=clang"`
- `CUDA_HOST_COMPILER` use an older gcc version for the cuda code.
  - `cmakeopt="-DCUDA_HOST_COMPILER=/usr/bin/gcc-5"`
- `XMR-STAK_LARGEGRID` use `32` or `64` bit integer for on device indices
  - default is enabled
  - on old GPUs it can increase the hash rate if disabled: `cmakeopt="-DXMR-STAK_LARGEGRID=OFF"`
  - if disabled it is not allowed to use more than `1000` threads on the device
- `XMR-STAK_THREADS` give the compiler information which value for `threads` is used at runtime
  - default is `0` (compile time optimization)
  - if the miner is compiled and used at runtime with the some value it can increase the hash rate: `cmakeopt="-DXMR-STAK_THREADS=32"`

### Alternatively, it is possible to run cmake directly without using the build.sh wrapper.
Two alternatives:
- use the ncurses GUI
  - `ccmake ..`
  - edit your options
  - end the GUI by pressing the key `c`(create) and than `g`(generate)
- set Options on the command line
  - enable a option: `cmake .. -DNAME_OF_THE_OPTION=ON`
  - disable a option `cmake .. -DNAME_OF_THE_OPTION=OFF`
  - set a value `cmake .. -DNAME_OF_THE_OPTION=value`

