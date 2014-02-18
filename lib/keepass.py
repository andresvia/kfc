# -*- coding: utf-8 -*-
# clases

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import keepassdb as kp
from . import util
import getpass


class entry_pair(object):
    def __init__(self):
        self.admin = None
        self.root = None


def open_db(dbfile):
    password = getpass.getpass("Password para abrir '%s': " % dbfile)
    db = kp.db.Database(dbfile, password)
    return(db)


def get_entries_for_group(db, groupName):
    super_parents = []
    entries = []
    for group in db.groups:
        if(group.title == groupName):
            super_parents.append(group)
    super_parents = [x for x in super_parents if x.parent not in super_parents]
    for super_parent in super_parents:
        entries += recursive_get_entries_for_group(super_parent)
    entries = [x for x in entries if
               x.title != "Meta-Info" and x.username != "SYSTEM"]
    return entries


def recursive_get_entries_for_group(group):
    entries = []
    for children in group.children:
        entries += recursive_get_entries_for_group(children)
    return(entries + group.entries)


def get_os_entries(entries):
    valid_os_entries = [x for x in entries if not util.valid_ip(x.title)]
    titles = set([x.title for x in valid_os_entries])
    os_entries = []
    for title in titles:
        os_entries.append(get_entry_pair(title, entries))
    return os_entries


def get_lom_entries(entries):
    return [x for x in entries if util.valid_ip(x.title)]


def get_entry_pair(entry_title, entries):
    possible_entries = [x for x in entries if x.title == entry_title]
    ep = entry_pair()
    for possible_entry in possible_entries:
        if (possible_entry.username != "root" and
              ep.admin is None):
            ep.admin = possible_entry
        elif (possible_entry.username == "root"):
            ep.root = possible_entry
    if ep.root is None:
        ep.root = ep.admin
    if ep.admin is None:
        ep.admin = ep.root
    return ep


def get_entry_path(entry):
    path = ""
    group = entry.group
    while group is not None:
        path = group.title + "/" + path
        group = group.parent
    return "/" + path
