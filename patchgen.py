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

import json
import urllib2
import md5
import re

from urlparse import urljoin

import os
import os.path
import platform
import sys

import subprocess

import fsutils

from Queue import Queue
from threading import Thread


# URL for Mojang's version list.
version_list_url = "http://s3.amazonaws.com/Minecraft.Download/versions/"

# Path to the temporary folder.
temp_dir_path = "tmp"

# Path to the jars folder.
jar_dir_path = "jars"

# Path to the output folder.
output_dir_path = "output"


# Filename for the index file.
index_file_name = "mcrw-index-v1.json"


# Determine the path to bsdiff
bsdiff_path = ""
if os.name == "nt":
	# On Windows, bsdiff is at bsdiff/bsdiff.exe
	bsdiff_path = "bsdiff/bsdiff.exe"

elif os.name == "posix":
	# In Posix systems, we'll try to find bsdiff installed on the system somewhere.
	print "Trying to find bsdiff..."

	proc = subprocess.Popen([ "which", "bsdiff" ], stdout = subprocess.PIPE)
	out, err = proc.communicate()

	bsdiff_path = out.strip()
	print "Found bsdiff at " + bsdiff_path
	if len(bsdiff_path) == 0:
		print "Could not find bsdiff. Aborting."
		exit(1)


else:
	print "Your operating system is not supported. Aborting."
	exit(1)

print "bsdiff path is " + bsdiff_path


def determine_latest_version():
	"""Reads from Mojang's version list and returns the name of the latest version of Minecraft."""

	response = urllib2.urlopen(urljoin(version_list_url, "versions.json"))
	json_str = response.read()

	data = json.loads(json_str)

	return data["latest"]["release"]


def execute_bsdiff(oldfile, newfile, patchfile):
	"""Runs bsdiff with the given arguments. Returns False on failure."""
	if subprocess.call([ bsdiff_path, oldfile, newfile, patchfile ]):
		return False
	else:
		return True


def download_version(mcversion, dest, max_tries = 3):
	"""Downloads the jar file with the given version number from Mojang's download site to the given output file."""
	try_count = 0
	
	while try_count < max_tries:
		response = urllib2.urlopen(urljoin(version_list_url, mcversion + "/" + mcversion + ".jar"))
		outfile = open(dest, "wb")
		info = response.info()

		etag = (info.getheaders("ETag")[0])[1:-1]
		size = int(info.getheaders("Content-Length")[0])
		print "Downloading %s bytes" % size

		# Ensure that the etag is a valid MD5
		if len(etag) != 32 or not re.findall(r"[a-fA-F\d]", etag):
			print "ETag " + etag + " is not a valid MD5. Aborting!"
			exit(1)

		m = md5.new()

		downloaded = 0
		block_sz = 8192
		while True:
			buf = response.read(block_sz)
			if not buf:
				break

			downloaded += len(buf)
			outfile.write(buf)
			m.update(buf)

			pcnt = int((float(downloaded) / float(size)) * 100)
			sys.stdout.write("\rDownloading jar file - %3d%% [%7d/%7d bytes]" % (pcnt, downloaded, size))
			sys.stdout.flush()

		sys.stdout.write("\n")
		sys.stdout.flush()

		outfile.close()

		digest = m.hexdigest()
		if digest == etag:
			print "Downloaded successfully"
			break
		elif try_count < max_tries:
			print "MD5 of downloaded data (%s) did not match the ETag (%s). Trying again." % (digest, etag)
			continue
		else:
			print "MD5 of downloaded data (%s) did not match the ETag (%s). Giving up after %d tries." % (digest, etag, try_count)
			exit(1)


def generate_patch(oldjar_path, patch_dest):
	"""
	Generates a patch from the latest jar to the file at oldjar_path.
	The patch will be saved to patch_dest.
	Returns a dict containing information about the version.
	"""

	vname, ext = os.path.splitext(os.path.basename(oldjar_path))

	# Generate the patch...
	if not execute_bsdiff(os.path.join(temp_dir_path, "latest.jar"), oldjar_path, patch_dest):
		print "bsdiff failed to execute. Aborting."
		exit(1)


	# Now check the MD5
	infile = open(oldjar_path, "rb")
	m = md5.new(infile.read())

	return { "name": vname, "md5": m.hexdigest() }


def generate_patches(worker_threads = 1):
	if not os.path.exists(jar_dir_path):
		print "No jars directory found at " + jar_dir_path

	if os.path.exists(temp_dir_path):
		fsutils.remove_recursive(temp_dir_path)
	os.mkdir(temp_dir_path)

	if os.path.exists(output_dir_path):
		fsutils.remove_recursive(output_dir_path)
	os.mkdir(output_dir_path)
	os.mkdir(os.path.join(output_dir_path, "patches"))

	latest_mc_version = determine_latest_version()

	print "Downloading latest minecraft.jar..."
	download_version(latest_mc_version, os.path.join(temp_dir_path, "latest.jar"))


	index = {
		"mcversion": latest_mc_version,
		"versions": [],
		"listversion": 1,
	}


	# Load all the patches into a queue.
	print "Generating patches..."
	patch_queue = Queue()
	for jarfile in os.listdir(jar_dir_path):
		fname, ext = os.path.splitext(os.path.basename(jarfile))

		if ext != ".jar":
			print "Skipping " + jarfile + " because it doesn't look like a jar file."
			continue
		
		patch_queue.put(os.path.join(jar_dir_path, jarfile))

	# Function for generating a patch. This will be run on a thread.
	def gen_patch():
		while not patch_queue.empty():
			jarfile = patch_queue.get()
			fname, ext = os.path.splitext(os.path.basename(jarfile))
			print "Generating patch for " + fname
			index["versions"].append(generate_patch(jarfile, os.path.join(output_dir_path, "patches", fname + ".patch")))
			patch_queue.task_done()

	for i in range(worker_threads):
		t = Thread(target = gen_patch)
		t.daemon = True
		t.start()

	patch_queue.join()

	# Dump the index to output.
	index_file = open(os.path.join(output_dir_path, index_file_name), "wb")
	index_file.write(json.dumps(index))
	index_file.close()


def new_version_available():
	"""
	Returns True if the "release" version specified on Mojang's version list is different from the "mcversion" specified in the index file.
	If there is no index file in the output directory, returns True anyways.
	"""
	json_str = ""
	try:
		index_file = open(os.path.join(output_dir_path, index_file_name), "r")
		json_str = index_file.read()
		index_file.close()
	except IOError:
		print "No valid index found. Assuming new version is available."
		return True

	index = json.loads(json_str)
	return determine_latest_version() != index["mcversion"]

def download_new_jar():
	"""Downloads the latest jar from Mojang's version list into the "jars" folder."""
	if not os.path.exists(jar_dir_path):
		os.mkdir(jar_dir_path)

	latest_version = determine_latest_version()
	print "Downloading new jar file..."
	download_version(latest_version, os.path.join(jar_dir_path, latest_version + ".jar"))

if __name__ == "__main__":
	# The number of worker threads that will be generating patches.
	wthreads = 1

	force_gen = False

	thread_arg_regex = re.compile(r"^-j([0-9]+)$")
	thread_args = [int(thread_arg_regex.search(arg).group(1)) for arg in sys.argv if thread_arg_regex.match(arg)]

	if len(thread_args) > 0:
		wthreads = thread_args[0]

	if "-f" in sys.argv:
		force_gen = True

	print "Running on %i threads." % wthreads

	new_version = new_version_available()

	if new_version:
		download_new_jar()

	if new_version or force_gen:
		generate_patches(wthreads)
	else:
		print "No new version found. Not doing anything. (to force generating patches, use -f)"
