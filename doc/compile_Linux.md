# Compile **CryptoGoblin** for Linux

## Install Dependencies

## AMD APP SDK 3.0 (only needed to use AMD GPUs)

- download and install the latest version from https://www.dropbox.com/sh/mpg882ekirnsfa7/AADWz5X-TgVdsmWt0QwMgTWLa/AMD-APP-SDKInstaller-v3.0.130.136-GA-linux64.tar.bz2?dl=0
  (do not wonder why it is a link to a dropbox but AMD has removed the SDK downloads, see https://community.amd.com/thread/228059)

## Cuda 8.0+ (only needed to use NVIDIA GPUs)

- download and install [https://developer.nvidia.com/cuda-downloads](https://developer.nvidia.com/cuda-downloads)
- for minimal install choose `Custom installation options` during the install and select
    - CUDA/Develpment
    - CUDA/Runtime
    - Driver components

## GNU Compiler

- Remember to edit build.sh before running it, use your favourite text editor, for example 'nano'.
- gcc and g++ version 5.1 or higher is required for full C++11 support. 
- Some newer gcc versions are not supported by CUDA (e.g. Ubuntu 17.10).
    - This will require installing gcc 5 and enabling the 'cudacomp' option in build.sh.

### Ubuntu / Debian
```bash
sudo apt install libmicrohttpd-dev libssl-dev cmake build-essential libhwloc-dev
git clone https://github.com/Dead2/CryptoGoblin.git
cd CryptoGoblin
# Edit build.sh
./build.sh
# (Optional:) make install
```

### Arch
```bash
sudo pacman -S --needed base-devel hwloc openssl cmake libmicrohttpd
git clone https://github.com/Dead2/CryptoGoblin.git
cd CryptoGoblin
# Edit build.sh
./build.sh
# (Optional:) make install
```

### Fedora
```bash
sudo dnf install gcc gcc-c++ hwloc-devel libmicrohttpd-devel libstdc++-static make openssl-devel cmake
git clone https://github.com/Dead2/CryptoGoblin.git
cd CryptoGoblin
# Edit build.sh
./build.sh
# (Optional:) make install
```

### CentOS
```bash
sudo yum install centos-release-scl epel-release
sudo yum install cmake3 devtoolset-7-gcc* hwloc-devel libmicrohttpd-devel openssl-devel make
scl enable devtoolset-7 bash
git clone https://github.com/Dead2/CryptoGoblin.git
cd CryptoGoblin
# Edit build.sh
./build.sh
# (Optional:) make install
```

### Ubuntu 14.04
```bash
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install gcc-5 g++-5 make
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-5 1 --slave /usr/bin/g++ g++ /usr/bin/g++-5
curl -L http://www.cmake.org/files/v3.4/cmake-3.4.1.tar.gz | tar -xvzf - -C /tmp/
cd /tmp/cmake-3.4.1/ && ./configure && make && sudo make install && cd -
sudo update-alternatives --install /usr/bin/cmake cmake /usr/local/bin/cmake 1 --force
sudo apt install libmicrohttpd-dev libssl-dev libhwloc-dev
git clone https://github.com/Dead2/CryptoGoblin.git
cd CryptoGoblin
* Edit build.sh, set cmake to 'cmake3'
./build.sh
# (Optional:) make install
```

### TinyCore Linux 8.x
TinyCore is 32-bit only, but there is an x86-64 port, known as "Pure 64,"
hosted on the TinyCore home page, and it works well.
Beware that huge page support is not enabled in the kernel distributed
with Pure 64.  Consider http://wiki.tinycorelinux.net/wiki:custom_kernel
Note that as of yet there are no distro packages for microhttpd or hwloc.
hwloc is easy enough to install manually though, shown below.
Also note that only CPU mining has been tested on this platform, thus the
disabling of CUDA and OpenCL shown below.
```bash
tce-load -iw openssl-dev.tcz cmake.tcz make.tcz gcc.tcz git.tcz \
         glibc_base-dev.tcz linux-4.8.1_api_headers.tcz glibc_add_lib.tcz
```
If you want the optional hwloc functionality, compile it first:
```bash
wget https://www.open-mpi.org/software/hwloc/v1.11/downloads/hwloc-1.11.8.tar.gz
tar xzvf hwloc-1.11.8.tar.gz
cd hwloc-1.11.8
./configure --prefix=/usr/local
make
sudo make install
cd ..
```
Then compile CryptoGoblin itself:
```bash
git clone http://github.com/Dead2/CryptoGoblin
cd CryptoGoblin
* Edit build.sh, set cmake to 'cmake3'
./build.sh
# (Optional:) make install
```
