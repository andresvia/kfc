# -*- coding: utf-8 -*-
# clases

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

# from fabric.api import run, env

from . import util
from . import keepass

unlang = ("LC_MESSAGES=C;export LC_MESSAGES;"
          "LC_ALL=C;export LC_ALL;"
          "LANG=C;export LANG;")


class access_object(object):
    def __init__(self):
        self.path = None
        self.host_string = None
        self.su_host_string = None
        self.password = None
        self.su_command = None
        self.su_username = None
        self.su_password = None
        self.access_pair = None


def get_opt_value(args, opt):
    for i in range(len(args)):
        if args[i] == opt and i < len(args):
            return args[i + 1]


def build_ssh_connect_string(username, hostname, port, password=None):
    if port is not None:
        port = ":" + str(port)
    else:
        port = ":22"
    if username is not None and username != "" and password is None:
        username = str(username) + "@"
    elif username is not None and username != "" and password is not None:
        username = str(username) + ":" + str(password) + "@"
    else:
        username = ""
    return util.xstr("%s%s%s" % (username, hostname, port))


def build_unix_su_command(username):
    su_cmnd = "su -"
    if username is None:
        username = ""
    else:
        username = " " + str(username)
    return util.xstr("%s%s%s -c" %
                     (unlang, su_cmnd, username))


def get_os_access_object(os_access_pair):
    a = access_object()
    a.host = os_access_pair.admin.title
    a.host_string = get_ssh_access(os_access_pair.admin)
    a.su_host_string = get_ssh_access(os_access_pair.root)
    a.path = keepass.get_entry_path(os_access_pair.admin) + a.host_string
    a.password = os_access_pair.admin.password
    a.su_command = get_su_access(os_access_pair.root)
    a.su_username = os_access_pair.root.username
    a.su_password = os_access_pair.root.password
    a.access_pair = os_access_pair
    return a


def get_ssh_access(os_admin_access):
    username = os_admin_access.username
    hostname = os_admin_access.title
    password = os_admin_access.password
    port = get_opt_value(os_admin_access.url.split(), "-P")
    connect_string = build_ssh_connect_string(username, hostname, port)
    unsafe_connect_string = build_ssh_connect_string(username,
                                                     hostname,
                                                     port,
                                                     password)
    connect_string.access = os_admin_access
    connect_string.unsafe = unsafe_connect_string
    return connect_string


def get_su_access(os_root_access):
    username = os_root_access.username
    su_command = build_unix_su_command(username)
    su_command.access = os_root_access
    return su_command
