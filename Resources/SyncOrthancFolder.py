#!/usr/bin/python

#
# This maintenance script updates the content of the "Orthanc" folder
# to match the latest version of the Orthanc source code.
#

import multiprocessing
import os
import stat
import urllib2

TARGET = os.path.join(os.path.dirname(__file__), 'Orthanc')
PLUGIN_SDK_VERSIONS = [ '0.9.5', '1.7.0' ]
REPOSITORY = 'https://hg.orthanc-server.com/orthanc/raw-file'

FILES = [
    'CMake/DownloadOrthancFramework.cmake',
    'LinuxStandardBaseToolchain.cmake',
    'MinGW-W64-Toolchain32.cmake',
    'MinGW-W64-Toolchain64.cmake',
    'MinGWToolchain.cmake',
]

SDK = [
    'orthanc/OrthancCPlugin.h',
]


def Download(x):
    branch = x[0]
    source = x[1]
    target = os.path.join(TARGET, x[2])
    print target

    try:
        os.makedirs(os.path.dirname(target))
    except:
        pass

    url = '%s/%s/%s' % (REPOSITORY, branch, source)

    with open(target, 'w') as f:
        f.write(urllib2.urlopen(url).read())


commands = []

for f in FILES:
    commands.append([ 'default',
                      os.path.join('Resources', f),
                      os.path.basename(f) ])

for f in SDK:
    for version in PLUGIN_SDK_VERSIONS:
        commands.append([
            'Orthanc-%s' % version, 
            'Plugins/Include/%s' % f,
            'Sdk-%s/%s' % (version, f) 
        ])


pool = multiprocessing.Pool(10)  # simultaneous downloads
pool.map(Download, commands)
