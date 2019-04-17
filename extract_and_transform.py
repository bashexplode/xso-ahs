#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import os
import subprocess
import fnmatch
import xml.etree.ElementTree as ET
import string
import platform
import base64
import binascii


class Extractor:
    basepath = '/var/db/dslocal/nodes/Default/users/'

    def get_macos_ver(self):
        return platform.release()

    def get_user_plist_filenames(self):
        files = []
        for filename in os.listdir(self.basepath):
            if fnmatch.fnmatch(filename, '[!_|!nobody]*.plist'):
                files.append(filename)

        return files

    def get_user_list(self):
        users = []
        pullusers = subprocess.Popen(['dscl', '.', '-list', '/Users'], stdout=subprocess.PIPE)
        allusers = pullusers.stdout.read()
        allusers = allusers.split('\n')
        for user in allusers:
            if "_" not in user and "daemon" not in user and "nobody" not in user and user != '':
                users.append(user)
        return users

    # adding directory services output for shadow hash data
    def get_shadowhashdata(self, user):
        cmd = u"dscl . -read /Users/{}".format(user) + u" ShadowHashData | sed 's/dsAttrTypeNative:ShadowHashData://' | tr -dc 0-9a-f | xxd -r-r -p | plutil -convert xml1 - -o -"
        ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = ps.communicate()[0]
        return result

    # in the new versions of macOS there are additional data sets in the XML file, so need to pull the first child
    def parse_plist_new(self, plist_str, user):
        root = ET.fromstring(plist_str)
        entropy = []
        iterations = []
        salt = []
        for child in root.findall(".//data[1]"):
            entropy.append(child.text.replace(" ", "").strip())
        entropy = ''.join(entropy[0].split())

        for child in root.findall(".//integer[1]"):
            iterations.append(child.text.replace(" ", "").strip())
        iterations = ''.join(iterations[0].split())

        for child in root.findall(".//data[2]"):
            salt.append(child.text.replace(" ", "").strip())
        salt = ''.join(salt[0].split())

        # Debugging
        # print(user + "'s base64 encoded salt: " + salt)
        # print(user + "'s base64 encoded entropy: " + entropy)
        # print(user + "'s iterations: " + iterations)

        # base64 decode entropy and salt
        entropy = self.b64_to_hex(entropy)
        salt = self.b64_to_hex(salt)

        # Debugging
        # print(user + "'s hex salt: " + salt)
        # print(user + "'s hex entropy: " + entropy)

        return {
            "entropy": entropy,
            "iterations": iterations,
            "salt": salt
        }

    def b64_to_hex(self, string):
        stringRaw = base64.b64decode(string)
        return stringRaw.encode("hex")

    # switching subprocess.run to subprocess.popen for backwards compatibility - Not tested
    def get_plist_contents_from(self, filename):
        path = self.basepath + filename
        # result = subprocess.Popen(['sudo', '/usr/bin/defaults', 'read', '{}'.format(path), 'ShadowHashData', '2>/dev/null', '|', 'tr', '-dc', '0-9a-f', '|', 'xxd', '-r' , '-p' , '|', 'plutil', '-convert', 'xml1', '-', '-o', '-'])
        cmd = u"sudo /usr/bin/defaults read {}".format(path) + u" ShadowHashData 2>/dev/null|tr -dc 0-9a-f|xxd -r -p| plutil -convert xml1 - -o -"
        ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = ps.communicate()[0]
        #result = subprocess.run([
        #    u"sudo /usr/bin/defaults read {}".format(path) +
        #    u" ShadowHashData 2>/dev/null|tr -dc 0-9a-f|xxd -r -p|" +
        #    u"plutil -convert xml1 - -o -"
        #], universal_newlines=True, shell=True,
        #   stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return result.stdout

    def remove_whitespace(self, hash_str):
        return hash_str.translate({
            ord(x): '' for x in set(string.whitespace)
        })

    # Updated for Popen formatting
    def parse_plist_old(self, plist_str):
        root = ET.fromstring(plist_str)
        for child in root.findall(".//data[1]"):
            entropy = child.text.replace(" ", "").strip()
        entropy = ''.join(entropy.split())

        for child in root.findall(".//integer[1]"):
            iterations = child.text.strip()
        iterations = ''.join(iterations.split())

        for child in root.findall(".//data[2]"):
            salt = child.text.strip()
        salt = ''.join(salt.split())

        # not sure if older version base64 encode the strings, so try base64 decode entropy and salt
        try:
            entropy = self.b64_to_hex(entropy)
            salt = self.b64_to_hex(salt)
        except binascii.Error:
            print "Not base64 encoded, moving on..."


        return {
            "entropy": entropy,
            "iterations": iterations,
            "salt": salt
        }

    def format_hash(self, hash_components):
        hash_str = self.remove_whitespace(
            u"$ml$" +
            hash_components["iterations"] +
            u"$" +
            hash_components["salt"] +
            u"$" +
            hash_components["entropy"]
        )
        return hash_str

    def make_crypt_format(self, user, hash_str):
        fmtd = "{}:{}".format(user, hash_str)
        return fmtd

    # Adding functionality to extract user hashes for macOS 10.13 and 10.14 - currently no way to get root hash
    def extract_password_hashes(self):
        hashes = []
        if platform.release() >= 17:
            users = self.get_user_list()
            for user in users:
                shadowhashdata = self.get_shadowhashdata(user)
                try:
                    hash_components = self.parse_plist_new(shadowhashdata, user)
                    formatted_hash = self.format_hash(hash_components)
                    hashes.append(self.make_crypt_format(user, formatted_hash))
                except:
                    hashes.append(u"Oops! Something went wrong trying to extract" +
                                  u" {}'s password hash!".format(user))
        else:
            files = self.get_user_plist_filenames()
            for filename in files:
                user = filename.split('.')[0]
                plist_contents = self.get_plist_contents_from(filename)
                try:
                    hash_components = self.parse_plist_old(plist_contents)
                    formatted_hash = self.format_hash(hash_components)
                    hashes.append(self.make_crypt_format(user, formatted_hash))
                except:
                    hashes.append(u"Oops! Something went wrong trying to extract" +
                                  u" {}'s password hash!".format(user))
        return hashes


if __name__ == '__main__':
    extractor = Extractor()
    hashes = extractor.extract_password_hashes()
    for hash_val in hashes:
        print(hash_val)
