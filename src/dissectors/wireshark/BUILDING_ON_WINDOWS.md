# Building Nox Wireshark dissectors on Window

To build the Wireshark dissectors, first go though the steps in the [" Win32/64: Step-by-Step Guide"](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html)  in the Wireshark developer manual to ensure you can build Wireshark correctly. One change is to replace the line `set(CMAKE_CXX_STANDARD 11)` to `set(CMAKE_CXX_STANDARD 17)` in the base `CMakeLists.txt` file in the Wireshark source root directory. Once that is done, you can follow the steps below.

To build the Nox Wireshark dissectors, copy the contents of the `src/dissectors/wireshark/n5305a` directory into a directory of the same name in `plugins/epan` directory in the Wireshark source tree.

After that is done, in the root of the Wireshark source directory, change the name of `CMakeListsCustom.txt.example` to `CMakeListsCustom.txt` and add the path to the `n5305a` dissector to the `CUSTOM_PLUGIN_SRC_DIR` set statement, it should look like the following:

```cmake
set(CUSTOM_PLUGIN_SRC_DIR
	plugins/epan/n5305a
)
```

Then rebuild Wireshark, if everything goes correctly then the native dissector will be in `run/<BUILD_TYPE>/plugins/<WS_VERSION>/epan/` directory as `n5305a.dll`
