MCRewind
========

MCRewind is an open-source project whose goal is to replace the now-defunct MCNostalgia.

It consists of a set of scripts for generating patches to downgrade the latest version of Minecraft to older versions. In addition to generating these patches, it also generates an 'index' file containing information about the generated patches. The index and patches can then be hosted on a webserver, where clients can read the index and download / use the patches.


Dependencies
------------

The patch generator needs the bsdiff4 python extension module. https://pypi.python.org/pypi/bsdiff4


License
=======

MCRewind is licensed under the MIT license.

Copyright (C) 2013 Andrew Okin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
