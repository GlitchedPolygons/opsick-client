# Opsick

## Client library

### Communicate with Opsick servers

---

This repo contains the C library for interacting with [Opsick](https://github.com/GlitchedPolygons/opsick) servers.

Check out the [API Documentation](https://glitchedpolygons.github.io/opsick-client) to find out more about all the
possible functions and how they are meant to be used.

### Cloning this repo

Navigate into a directory where you wish to clone the opsick client lib repository into. Then, run:

`git clone --recursive https://github.com/GlitchedPolygons/opsick-client`

This should fetch all dependencies (included in this repo as git submodules) and check them out under `lib/`.

Dependencies:

* [CECIES](https://github.com/GlitchedPolygons/cecies)
* [Pwcrypt](https://github.com/GlitchedPolygons/pwcrypt)
* [Jsmn](https://github.com/zserge/jsmn)
* [Ed25519](https://github.com/GlitchedPolygons/GlitchEd25519)
* [GlitchedHTTPS](https://github.com/GlitchedPolygons/glitchedhttps)

### Building

If you choose to build from src, make sure that you have the necessary build tools installed, such as [CMake](https://cmake.org), a compiler, and so on...

Then, either run the [build.sh](https://github.com/GlitchedPolygons/opsick-client/blob/master/build.sh) shell script **OR** execute the following commands:

```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

### API Documentation

Available here: https://glitchedpolygons.github.io/opsick-client