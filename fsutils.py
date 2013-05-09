# Copyright (C) 2013 Andrew Okin

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import os
import os.path

def remove_recursive(path, follow_symlinks = False):
	"""
	Recursively deletes whatever is at the given path.
	If it is a directory, calls remove_recursive() for each file or subdirectory in the directory.
	If it is a file, removes the file.
	Returns True on success and False if something failed to be deleted.
	If follow_symlinks is True, will recurse into any symlink that points to a directory. Otherwise, the symlink will just be deleted.
	"""

	if os.path.isfile(path) or (os.path.islink(path) and not follow_symlinks):
		# If it's a file or if follow_symlinks is off and it's a symlink, then simply delete it.
		os.remove(path)

	elif os.path.isdir(path):
		# If it's a directory, recurse into the directory and then remove the directory.
		for filename in os.listdir(path):
			remove_recursive(os.path.join(path, filename), follow_symlinks)
		os.rmdir(path)
