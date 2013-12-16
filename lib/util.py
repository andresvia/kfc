# -*- coding: utf-8 -*-
# clases

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import socket


class xstr(str):
    def __init__(self, string):
        super(xstr, self).__init__()


def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False
