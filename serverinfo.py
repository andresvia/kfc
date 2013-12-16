# -*- coding: utf-8 -*-
# seq

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import os
import sys
import re
import ConfigParser as configparser

from lib import keepass as kp
from lib import cache

appname = 'serverinfo'

configdir = os.path.join(os.path.expanduser('~'), "%s" % appname)

if not os.path.isdir(configdir):
    print("ERROR: No existe el directorio de configuración '%s'" % configdir)
    sys.exit(0)

configfiles = []

for root, dirs, files in os.walk(configdir):
    for d in dirs:
        dirs.remove(d)
    for f in files:
        if (re.match('.*\.ini$', f, re.I)):
            configfiles.append(os.path.join(root, f))

config = configparser.ConfigParser(allow_no_value=True)
configfiles = config.read(configfiles)

oses = []

cache_pickle = None
cache_size = None
cache_max_age = None

for section in config.sections():
    if section.lower() != "global":
        db = config.get(section, 'keepassdb')
        group = config.get(section, 'group')
        db = kp.open_db(db)
        all_entries = kp.get_entries_for_group(db, group)
        oses += kp.get_os_entries(all_entries)
    else:
        cache_pickle = config.get(section, 'cache_store')
        cache_size = int(config.get(section, 'cache_size'))
        cache_max_age = int(config.get(section, 'cache_max_age'))

if cache_pickle is None or cache_size is None or cache_max_age is None:
    print("ERROR: No especifica configuracion de cache")
    sys.exit(0)

server_info_cache = cache.Cache(cache_pickle, cache_size, cache_max_age)
