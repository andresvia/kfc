# -*- coding: utf-8 -*-
# clases

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import socket
import os
import sys
import subprocess


class xstr(str):
    def __init__(self, string):
        super(xstr, self).__init__()


class xlist(list):
    def __init__(self):
        super(xlist, self).__init__()


def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False


# thanks http://stackoverflow.com/a/17317468
def open_file(filename):
    if sys.platform == "win32":
        os.startfile(filename)
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, filename])


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False
