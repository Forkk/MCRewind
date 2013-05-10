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
import md5
import re

import urllib2
import requests

from urlparse import urljoin

import argparse
import os
import sys
import shutil

from Queue import Queue
from threading import Thread

import bsdiff4


#####################
# UTILITY FUNCTIONS #
#####################

def determine_latest_version(mojang_versions_url):
	"""Reads from Mojang's version list and returns the name of the latest version of Minecraft."""

	response = urllib2.urlopen(urljoin(mojang_versions_url, "versions.json"))
	json_str = response.read()

	data = json.loads(json_str)

	return data["latest"]["release"]


def is_valid_md5(md5str):
	return len(md5str) == 32 and re.findall(r"[a-fA-F\d]", md5str)


def get_index_mcversion(index_path):
	"""
	read the minecraft version from the index file.
	return <index mcversion or None>
	"""
	if os.path.exists(index_path):
		index = json.load(open(index_path, "r"))
		return index["mcversion"]
	return None


def download_version(mojang_versions_url, mcversion, dest, max_tries = 3):
	"""Downloads the jar file with the given version number from Mojang's download site to the given output file."""
	pass


def generate_patch(version, old_jar, patch, latest_jar):
	"""
	Generates a diff between latest_jar and old_jar in patch
	"""
	bsdiff4.file_diff(latest_jar, old_jar, patch)

	result = {"name": version}
	with open(old_jar, "rb") as fp:
		result["md5"] = md5.new(fp.read()).hexdigest()

	return result



#########
# TASKS #
#########

def check_new_jars(jar_dir_path, cache_file_path, mojang_versions_url, verbose = False):
	"""
	Checks to see if a new jar file should be downloaded.

	If verbose is true, the function will print a bunch of crap about what's going on. Primarily reasons why it has determined that there's a new version.

	Returns the version name of the new jar if there is one. Otherwise, return an empty string.
	"""

	# This is probably a monstrosity, but I don't want to have to type this crap out 20 times...
	def print_new_version_reason(msg):
		print("Assuming there's a new version because %s" % msg)

	# First, get the version name of the latest minecraft.jar 
	latest_version_name = determine_latest_version(mojang_versions_url)

	# Next, we need to make sure the cache file exists. If it doesn't, assume there's a new version.
	if not os.path.exists(cache_file_path):
		if verbose: print_new_version_reason("the cache file doesn't exist.")
		return latest_version_name

	# Now we load the cache file.
	cache_info = {}
	with open(cache_file_path, "r") as cahce_file: cache_info = json.load(cahce_file) # TODO: Handle syntax errors

	# Ensure the cache is valid.
	if not "mcversion" in cache_info or not "md5sum" in cache_info:
		if verbose: print_new_version_reason("the cache file is missing fields.")
		return latest_version_name

	# Make sure the cache file's mcversion name matches the latest version name.
	if cache_info["mcversion"] != latest_version_name:
		if verbose: print_new_version_reason("the mcversion specified in the cache file doesn't match the latest version.")
		return latest_version_name

	# Determine the path to the latest jar
	latest_jar_path = os.path.join(jar_dir_path, latest_version_name + ".jar")

	# Make sure we have a jar file in our jars folder matching this version name.
	if not os.path.exists(latest_jar_path):
		if verbose: print_new_version_reason("no jar file found matching the mcversion specified in the cache file.")
		return latest_version_name

	# Get the ETag for the latest jar file.
	req = requests.head(mojang_versions_url + "{0}/{0}.jar".format(latest_version_name))
	req.raise_for_status()
	etag = req.headers['ETag'][1:-1]

	# Make sure the ETag is a valid MD5sum. If not, error.
	if not is_valid_md5(etag):
		print("ETag %s is not a valid MD5sum. Aborting!" % etag)
		if verbose: print_new_version_reason("the ETag received from the version list is not a valid MD5sum.")
		return "" # TODO: Should return an error here.

	# Check if the ETag matches the MD5sum field in the cache file.
	if etag != cache_info["md5sum"]:
		if verbose: print_new_version_reason("the ETag on the version list (%s) doesn't match the one in the cache file (%s)." %
											(etag, cache_info["md5sum"]))
		return latest_version_name

	# Next we calculate the MD5sum of the already downloaded file in our jars folder and make sure it matches too.
	jar_md5 = md5.new()
	with open(latest_jar_path, "rb") as jar: jar_md5.update(jar.read())
	if etag != jar_md5.hexdigest():
		if verbose: print_new_version_reason("the MD5sum of the jar file doesn't match the ETag or the one in the cache file.")
		return latest_version_name

	# Now that all of these checks have passed, we can be almost absolutely sure that the version we have in the jars folder is actually the version we want. Return empty string, indicating that we don't need to download anything.
	return ""


def download_latest_jar(latest_version_name, cache_file_path, mojang_versions_url,
						dest, max_tries = 3, show_progress_indicator = False):
	"""
	Downloads the latest minecraft.jar from Mojang's version list site and writes info about it to the cache file.

	latest_version_name specifies the version name for the minecraft.jar that should be downloaded as the latest version.

	returns < 0 if successful, otherwise positive number > 1
	"""

	try_count = 0
	jar_md5 = None

	# First, download the file and make sure it's valid.
	while try_count < max_tries:

		# Open URL and file streams for reading / writing.
		response = urllib2.urlopen(urljoin(mojang_versions_url, "{0}/{0}.jar".format(latest_version_name)))
		outfile = open(dest, "wb")


		# Get header info.
		info = response.info()

		# Get the ETag field from the header.
		etag = (info.getheaders("ETag")[0])[1:-1]
		size = int(info.getheaders("Content-Length")[0])
		print("Downloading %i bytes" % size)

		# Ensure that the etag is a valid MD5
		if not is_valid_md5(etag):
			print("ETag %s is not a valid MD5. Aborting!" % etag)
			return 1


		# Create a new MD5 object for the data we're downloading.
		md5obj = md5.new()

		# Download data and pass it to the MD5 object as we download it.
		downloaded = 0
		block_sz = 8192
		while True:
			buf = response.read(block_sz)
			if not buf:
				break

			downloaded += len(buf)
			outfile.write(buf)
			md5obj.update(buf)

			# Show a progress indicator if it's enabled.
			if show_progress_indicator:
				pcnt = int((float(downloaded) / float(size)) * 100)
				print("\rDownloading jar file - %3d%% [%7d/%7d bytes]" % (pcnt, downloaded, size), end="")

		sys.stdout.write("\n")
		sys.stdout.flush()

		outfile.close()

		jar_md5 = md5obj.hexdigest()
		if jar_md5 == etag:
			# If the download succeeded, break the loop.
			break

		elif try_count < max_tries:
			# Otherwise, print a warning and continue.
			print("MD5 of downloaded data (%s) did not match the ETag (%s). Trying again." % (jar_md5, etag))
			continue

		else:
			# If we've tried too many times, give up.
			print("MD5 of downloaded data (%s) did not match the ETag (%s). Giving up after %d tries." % (digest, etag, try_count))
			return 1


	# Now that we've downloaded the file, we need to store the information in the cache file.
	# Luckily, Python is fucking awesome.
	with open(cache_file_path, "w") as cache_file:
		json.dump({ "mcversion": latest_version_name, "md5sum": jar_md5 }, cache_file)


	return 0


def generate_patches(worker_threads, jar_dir_path, output_dir_path, index_file_name, latest_mc_version):
	"""
	Generates patches.

	worker_threads specifies how many bsdiff threads to run at once.
	latest_mc_version specifies the version name of the latest Minecraft version.
	returns < 0 if successful, otherwise positive number > 1
	"""

	if not os.path.exists(jar_dir_path):
		print("No jars directory found at %s" % jar_dir_path)
		return 2

	if os.path.exists(output_dir_path):
		shutil.rmtree(output_dir_path)
	os.mkdir(output_dir_path)

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



	# Thread function for patch generation workers.
	def patchgen_worker():
		while not patch_queue.empty():
			jarfile = patch_queue.get()
			fname, ext = os.path.splitext(os.path.basename(jarfile))

			print("Generating patch for %s" % fname)
			index["versions"].append(generate_patch(fname, jarfile, 
				os.path.join(output_dir_path, "%s.patch" % fname), latest_jar_path))

			patch_queue.task_done()


	for i in range(worker_threads):
		t = Thread(target = patchgen_worker)
		t.daemon = True
		t.start()

	patch_queue.join()

	# Dump the index to output
	print("Writing Index...")
	with open(index_file_name, "w") as index_file:
		json.dump(index, index_file)
	
	return 0


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
						help="Don't check for a new minecraft version (implies -f)")

	parser.add_argument("-v", "--verbose", default=False, action="store_true",
						help="Enables verbose output.")


	p_dirs = parser.add_argument_group("Paths")
	p_dirs.add_argument("-o", "--output-dir", default="patches",
						help="The output directory [%(default)s]", metavar="DIR")

	p_dirs.add_argument("-i", "--jar-dir", default="jars",
						help="The directory containing the .jar files [%(default)s]", metavar="DIR")

	p_dirs.add_argument("-x", "--index-file", default="index.json",
						help="Path specifying where the index file should be generated [%(default)s]", metavar="INDEX")

	p_dirs.add_argument("-c", "--cache-file", default="cache.json",
						help="Path specifying where the cache file should be put [%(default)s]", metavar="CACHE")

	args = parser.parse_args(argv[1:])



	print("MCRewind Patch Generator v1")

	print("Force generate patches? %s" % str(args.force))
	print("Worker Threads: %i" % args.threads)
	print("Mojang versions URL: %s" % args.mojang_versions)
	print("Offline mode? %s" % str(args.offline))

	print("Jar file directory: %s" % args.jar_dir)
	print("Output directory: %s" % args.output_dir)
	print("Index file path: %s" % args.index_file)
	print("Cache file path: %s" % args.cache_file)
	print("")

	mcversion = get_index_mcversion(args.index_file)

	new_version = None
	if not args.offline:
		print("Checking for a new minecraft version...")

		# Call check_new_jars to see if there's a new version.
		new_version = check_new_jars(args.jar_dir, args.cache_file, args.mojang_versions, 
			verbose = args.verbose)

		# If there's a new version.
		if new_version:
			print("Found new Minecraft version: %s" % new_version)

			# Download the new version.
			dest = os.path.join(args.jar_dir, "%s.jar" % new_version)
			retval = download_latest_jar(new_version, args.cache_file, args.mojang_versions, dest, 
				show_progress_indicator = True)
			if retval > 0:
				print("Error getting latest jar. Aborting.")
				return retval
		
		# _, new_version = check_new_version(mcversion, args.mojang_versions)
		# if new_version:
		# 	print("New Minecraft version found: %s" % new_version)
		# 	dest = os.path.join(args.jar_dir, "%s.jar" % new_version)
		# 	if os.path.exists(dest):
		# 		print("Found new version in JAR directory.")
		# 	else:
		# 		download_version(args.mojang_versions, new_version, dest)
	else:
		print("Skipping update check.")

	if not (new_version or args.force or args.offline):
		print("No new version found, not doing anything.")
		return 0

	# Yes, this else is unnecessary, but it makes it easier to tell what's going on here.
	else:
		if not mcversion and not new_version:
			print("Can't generate patches because no cache or index file could be found.")
			return 1

		print("Generating patches...")

		result = generate_patches(args.threads, args.jar_dir, args.output_dir, 
			args.index_file, (new_version if new_version else mcversion))

		if result != 0:
			return result

		print("Done.")
		return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))

