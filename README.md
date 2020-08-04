Zebracorn
==============

Zebracorn is a lightweight, multi-platform, multi-architecture CPU emulator framework
based on a fork of [Unicorn](http://www.unicorn-engine.org).

The API is identical to Unicorn, but Zebracorn offers a few additional features:

- Hooks:
  - RDTSC instruction
  - Block Translation
  - Callback after N blocks executed
- Execution Info:
  - Block count executed
  - Instruction count executed
- Instruction Meta:
  - Tiny Code Generator (TCG) representation of each instruction
- Unicorn AFL integration

These APIs are only supported through the Python bindings.


The Zebracorn engine is primarily made available to support functionality in the [zelos binary emulator](https://github.com/zeropointdynamics/zelos).

Installation
------------

Zebracorn is distributed as a python `pip` package. Other bindings are not supported. To install the python package:

```bash
$ pip install zebracorn
```

Python packages are available for Windows, Linux and MacOS.

License
-------

Unicorn and Qemu are released under the [GPL license](COPYING).
