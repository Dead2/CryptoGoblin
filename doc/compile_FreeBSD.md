# Compile **CryptoGoblin** for FreeBSD

## Install Dependencies

*Note: This guide is tested for FreeBSD 11.0-RELEASE*

From the root shell, run the following commands:

    pkg install git libmicrohttpd hwloc cmake 

Type 'y' and hit enter to proceed with installing the packages.

    git clone https://github.com/Dead2/CryptoGoblin.git
    mkdir CryptoGoblin/build
    cd CryptoGoblin/build
    cmake ..
    make install

Now you have the binary located at "bin/CryptoGoblin" and the needed shared libraries.
