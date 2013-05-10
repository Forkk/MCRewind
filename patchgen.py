#!/usr/bin/env python
# vim: noet
# ---------------------------------------------------------------------------
# Copyright (C) 2013 Andrew Okin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ---------------------------------------------------------------------------
# Future
from __future__ import print_function, unicode_literals, absolute_import

# IMPORTS
import json
import urllib2
import md5
import re

from urlparse import urljoin

import argparse
import os
import sys
import shutil

from Queue import Queue
from threading import Thread

import bsdiff4


def download_version(mojang_versions_url, mcversion, dest, max_tries = 3):
	"""Downloads the jar file with the given version number from Mojang's download site to the given output file."""
	try_count = 0

	while try_count < max_tries:
		response = urllib2.urlopen(urljoin(mojang_versions_url, "{0}/{0}.jar".format(mcversion)))
		outfile = open(dest, "wb")
		info = response.info()

		etag = (info.getheaders("ETag")[0])[1:-1]
		size = int(info.getheaders("Content-Length")[0])
		print("Downloading %i bytes" % size)

		# Ensure that the etag is a valid MD5
		if len(etag) != 32 or not re.findall(r"[a-fA-F\d]", etag):
			print("ETag %s is not a valid MD5. Aborting!" % etag)
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
			print("\rDownloading jar file - %3d%% [%7d/%7d bytes]" % (pcnt, downloaded, size), end="")

		sys.stdout.write("\n")
		sys.stdout.flush()

		outfile.close()

		digest = m.hexdigest()
		if digest == etag:
			print("Downloaded successfully")
			break
		elif try_count < max_tries:
			print("MD5 of downloaded data (%s) did not match the ETag (%s). Trying again." % (digest, etag))
			continue
		else:
			print("MD5 of downloaded data (%s) did not match the ETag (%s). Giving up after %d tries." % (digest, etag, try_count))
			exit(1)


def generate_patch(version, old_jar, patch, latest_jar):
	"""
	Generates a diff between latest_jar and old_jar in patch
	"""
	bsdiff4.file_diff(latest_jar, old_jar, patch)

	result = {"name": version}
	with open(old_jar, "rb") as fp:
		result["md5"] = md5.new(fp.read()).hexdigest()

	return result


def generate_patches(worker_threads, jar_dir_path, output_dir_path, index_file_name, latest_mc_version):
	"""
	Generates patches.

	worker_threads specifies how many bsdiff threads to run at once.
	latest_jar_path specifies a path to the latest Minecraft jar file. If this is unspecified, the latest version will be downloaded automatically.
	returns <0 if successful, otherwise positive number above 1>
	"""

	if not os.path.exists(jar_dir_path):
		print("No jars directory found at %s" % jar_dir_path)
		return 2

	if os.path.exists(output_dir_path):
		shutil.rmtree(output_dir_path)
	os.mkdir(output_dir_path)
	os.mkdir(os.path.join(output_dir_path, "patches"))

	index = {
		"mcversion": latest_mc_version,
		"versions": [],
		"listversion": 1,
	}

	latest_jar_path = os.path.join(jar_dir_path, "%s.jar" % latest_mc_version)

	# Load all the patches into a queue.
	patch_queue = Queue()
	for jarfile in os.listdir(jar_dir_path):
		fname, ext = os.path.splitext(os.path.basename(jarfile))

		if ext != ".jar":
			print("Skipping %s because it doesn't look like a jar file." % jarfile)
			continue
		
		patch_queue.put(os.path.join(jar_dir_path, jarfile))

	# Function for generating a patch. This will be run on a thread.
	def gen_patch():
		while not patch_queue.empty():
			jarfile = patch_queue.get()
			fname, ext = os.path.splitext(os.path.basename(jarfile))
			print("Generating patch for %s" % fname)
			index["versions"].append(generate_patch(fname, jarfile, os.path.join(output_dir_path, "patches", "%s.patch" % fname), latest_jar_path))
			patch_queue.task_done()

	for i in range(worker_threads):
		t = Thread(target = gen_patch)
		t.daemon = True
		t.start()

	patch_queue.join()

	# Dump the index to output
	print("Writing Index...")
	with open(os.path.join(output_dir_path, index_file_name), "wb") as index_file:
		json.dump(index, index_file)
	
	return 0


def get_index_mcversion(output_dir, index_file):
	"""
	read the minecraft version from the index file.
	return <index mcversion or None>
	"""
	idx = os.path.join(output_dir, index_file)
	if os.path.exists(idx):
		index = json.load(open(idx, "r"))
		return index["mcversion"]
	return None


def check_new_version(current_version, mojang_versions_url):
	"""
	check if mojang has a new version.
	return <mojang reply>, <new version or None>
	"""
	mojang = json.load(urllib2.urlopen(mojang_versions_url + "versions.json"))

	if mojang["latest"]["release"] != current_version:
		return mojang, mojang["latest"]["release"]
	return mojang, None


def main(argv):
	""" Main function """
	parser = argparse.ArgumentParser(prog=argv[0], description="MCRewind patchserver generator")
	parser.add_argument("-f", "--force", default=False, action="store_true",
						help="Force patch generation")
	parser.add_argument("-j", "--threads", default=1, type=int,
						help="Anmount of worker threads [%(default)s]", metavar="T")
	parser.add_argument("-a", "--mojang-versions", default="http://s3.amazonaws.com/Minecraft.Download/versions/",
						help="The url to Mojang's versions.json", metavar="URL")
	parser.add_argument("-n", "--offline", default=False, action="store_true",
						help="Don't check for a new minecraft version online (implies -f)")
	p_dirs = parser.add_argument_group("Locations")
	p_dirs.add_argument("-o", "--output-dir", default="output",
						help="The output directory [%(default)s]", metavar="DIR")
	p_dirs.add_argument("-i", "--jar-dir", default="jars",
						help="The directory containing the .jar files [%(default)s]", metavar="DIR")
	p_dirs.add_argument("-x", "--index-file", default="index.json",
						help="The patch index file name [%(default)s]", metavar="IDX")
	args = parser.parse_args(argv[1:])

	print("MCRewind Patch Generator v1")

	mcversion = get_index_mcversion(args.output_dir, args.index_file)
	print("Minecraft Version: %s" % mcversion)

	new_version = None
	if not args.offline:
		print("Checking for a new minecraft version...")
		_, new_version = check_new_version(mcversion, args.mojang_versions)
		if new_version:
			print("New Minecraft version found: %s" % new_version)
			dest = os.path.join(args.jar_dir, "%s.jar" % new_version)
			if os.path.exists(dest):
				print("Found new version in JAR directory.")
			else:
				download_version(args.mojang_versions, new_version, dest)
	else:
		print("Skipping update check.")

	if not (new_version or args.force or args.offline):
		print("No new version found, not doing anything.")
		return 1

	# begin
	print("JAR Directory: %s" % args.jar_dir)
	print("OUT Directory: %s" % args.output_dir)
	print("Index Filename: %s" % args.index_file)
	print("Worker Threads: %i" % args.threads)

	print("Generating patches...")
	r = generate_patches(args.threads, args.jar_dir, args.output_dir, args.index_file, (new_version if new_version else mcversion))
	if r != 0:
		return r

	print("Done.")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))

