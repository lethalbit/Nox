# Nox ![Nox Build](https://github.com/lethalbit/Nox/workflows/Nox%20Build/badge.svg) [![Total alerts](https://img.shields.io/lgtm/alerts/g/lethalbit/Nox.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/lethalbit/Nox/alerts/)

Nox is a project that consists of an interface library and a GUI and CLI client for interacting with the Agilent N5540A and it's supported modules.


## Supported Modules

The following table shows the current supported operations per module

| Module | Boot | Diagnostics | Gateware Load | Firmware Update | Analysis |
|--------|------|-------------|---------------|-----------------|----------|
| N5305A | Done | TODO        | TODO          | TODO?           | TODO     |
| N5306A | TODO | TODO        | TODO          | TODO?           | TODO     |



## Configuring and Building

### Prerequisites

To build Nox, ensure you have the following build time dependencies:
 * git
 * meson
 * ninja
 * zlib >= 1.1.130
 * g++ >= 8.4.0 or clang++ >= 8.0.1

For `nox-gui` you will also need the QT5 development packages installed.


And finally for `nox-cli` only one of the following depending on the line editor configuration as well as `ncurses`:
 * libedit
 * libreadline




While Nox also depends on [substrate](https://github.com/bad-alloc-heavy-industries/substrate), if it's not already installed on your system the build system will download and build the dependency for you automatically.

### Configuring

You can build Nox with the default options, all of which can be found in [`meson_options.txt`](meson_options.txt). You can change these by specifying `-D<OPTION_NAME>=<VALUE>` at initial meson invocation time, or with `meson configure` in the build directory post initial configure.

To change the install prefix, which is `/usr/local` by default ensure to pass `--prefix <PREFIX>` when running meson for the first time.

In either case, simpling running `meson build` from the root of the repository will be sufficient and place all of the build files in the `build` subdirectory.

### Building

Once you have configured Nox appropriately, to simply build and install simply run the following:

```
$ ninja -C build
$ ninja -C build install
```

This will build and install Nox into the default prefix which is `/usr/local`, to change that see the configuration steps above.

### Notes to Package Maintainers

If you are building Nox for inclusion in a distributions package system then ensure to set `DESTDIR` prior to running meson install.

There is also a `bugreport_url` configuration option that is set to this repositories issues tracker by default, it is recommended to change it to your distributions bug tracking page.

## Contributing

If you would like to contribute to Nox, please see the  [Nox Contribution Guidelines](https://github.com/lethalbit/Nox/blob/main/CONTRIBUTING.md).

## License

`nox-cli` and `nox-gui` are licensed under the GPL v3 or later, you can find a full copy of the license text in the [`LICENSE`](LICENSE) file.

`libnox` is licensed under the LGPL v3 or later, you can find a full copy of the license text in the [`LICENSE.libnox`](LICENSE.libnox) file.
