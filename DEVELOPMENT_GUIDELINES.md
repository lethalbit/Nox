# Nox Development Guidelines

The following document describes the guidelines to follow when working on and contributing to Nox.

## Licensing

For all original code, [SPDX license identifiers](https://spdx.github.io/spdx-spec/appendix-V-using-SPDX-short-identifiers-in-source-files/) must be used at the top of each file to denote the license that is appropriate for that file. In the case of [`libnox`](https://github.com/lethalbit/Nox/src/libnox) that would be something like `// SPDX-License-Identifier: LGPL-3.0-or-later`

## File Naming

All files must be in lowercase and use snake case as the naming convention. So rather than `ThisIsAfilename` it would be `this_is_a_file_name`.

For C++ source files and headers, the file extensions `.cc` and `.hh` must be used for each respectively.

## Project Structure

All of the components in Nox are structured like this, so any additions must conform unless otherwise approved.

Inside the `src` directory, each project is broken into it's own directory, the `meson.build` in the root `src` directory simply `subdir`'s each of these directories.

Within each project directory there is the root `meson.build` file for this project, as well as an `include` directory. The tree between the project root and the `include` directory must be mirrored to maintain consistency. 

You must also break up the source files into a directory hierarchy that is sane and maintainable. Separate source files based on where in the software they fit and their functionality, don't just pile everything in one directory.

## Coding Style

Please match the coding style the rest of the project uses depending on the language. See how things are formatted in the other files for the project to ensure that your changes match.

## Commits

All commits done must be signed, all changes in unsigned commits will be rejected. 
