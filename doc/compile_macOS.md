# Compile **CryptoGoblin** for macOS

## Installing dependencies

Assuming you already have [Homebrew](https://brew.sh) installed, the installation of dependencies is pretty straightforward and will generate the `CryptoGoblin` binary in the `build/bin/` directory.


### Common
```bash
brew install hwloc libmicrohttpd gcc openssl cmake
```

### For NVIDIA GPUs
```bash
brew tap caskroom/drivers
brew cask install nvidia-cuda
```

## Compiling
```bash
    git clone https://github.com/Dead2/CryptoGoblin.git
    cd CryptoGoblin
    # Edit build.sh
    ./build.sh
    # (Optional:) make install
```
