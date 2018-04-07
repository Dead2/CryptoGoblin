# Compile **CryptoGoblin** for FreeBSD

## Install Dependencies

*Note: This guide is tested for FreeBSD 11.0-RELEASE*

From the root shell, run the following commands:

```bash
    pkg install git libmicrohttpd hwloc cmake 
```
Type 'y' and hit enter to proceed with installing the packages.

```bash
    git clone https://github.com/Dead2/CryptoGoblin.git
    cd CryptoGoblin
    # Edit build.sh
    ./build.sh
    # (Optional:) make install
```

Now you have the binary located at "build/bin/CryptoGoblin" and the needed shared libraries.
