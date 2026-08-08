# Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Dependencies](#dependencies)
4. [Build](#build)
5. [Usage](#usage)
6. [Documentation](#documentation)
7. [Notes](#notes)
8. [Contributing](#contributing)

# Introduction
**libwgcpp** is simple easy-to-use embeddable-wg-library C++ wrapper library
with flexible API. It is compatible to embeddable-wg-library and use it's API
with minimum overhead as possible

# Features
* Flexible easy-to-use API
* Move semantics support
* Several thread safety modes. No manual intervention is required.
Thread **safe** is used by default
* RAII based architecture. Your are not obligated to (de-)allocate memory
on your own
* Minimum overhead over C library
* Standart instruments are used. No more addictive external libraries. 
* Permissive LGPL-3 license

# Dependencies
**libwgcpp** use as dependencies only:
* libc
* C++17 STL

# Build
Project uses CMake-3.15+. To build as a shared library (.so):

For Github:
```shell
git clone -b master https://github.com/fluffymax2005/libwgcpp.git
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

For Giverse mirror:
```shell
git clone -b master https://gitverse.ru/fluffymax2005/libwgcpp.git
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

Otherwise you can integrate library as a part of your project. Just
copy ```include``` and ```src``` files into your project. Most
of headers are template based so there would be no big deal to
recompile.

# Usage
Simple examples to introduce usage of library can be found in
```examples``` directory. You should read README by that path as
well to avoid errors.

# Documentation
Library support Doxygen to generate documentation. By default HTML and man
based docs is used. To generate it:
```bash
cd docs
doxygen
```
```html``` and ```man``` directories will appear there.

# Notes
As **libwgcpp** support single and multi threaded modes. Thus you 
**should** figure out which you are going to use because copy
constructors are unavailable to used due to ```std::mutex``` and
```std::lock_guard``` in multi threaded mode. Otherwise you get
compile time errors.

# Contributing
If found any (critial) vulnerabilities create 
[issue]("https://github.com/fluffymax2005/libwgcpp/issues/new")
on Github and tell about it using template:
* Brief description of vulnerability
* File(s) where you found it
* Why your found is critical
* (Optional) Your suggestions to fix problem