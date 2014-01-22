# -*- coding: utf-8 -*-
# clases

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import re
import sys

from fabric.contrib.console import confirm
from fabric.api import env

unix = __import__("lib.unix").unix


class Server(object):
    def __init__(self, oses):

        if hasattr(env, 'os_filter'):
            os_filter = env.os_filter
        else:
            os_filter = ""

        if os_filter == "":
            print("No hay un filtro de SO, establezca un filtro con "
                  "--set os_filter=filtro o confirme para ejecutar las tareas "
                  "sobre todos los servidores")
            if not confirm("¿Ejecutar las tareas sobre todos los servidores?"):
                sys.exit(1)

        os_filter = ".*%s.*" % os_filter

        env.shell = "/bin/sh -c"

        self.access_dict = {}

        for os_access_pair in oses:
            a = unix.get_os_access_object(os_access_pair)
            host_string = a.host_string
            password = a.password
            self.access_dict[host_string] = a

        for k in self.access_dict:
            if re.match(os_filter, self.access_dict[k].path, re.I):
                host_string = self.access_dict[k].host_string
                password = self.access_dict[k].password
                env.hosts.append(host_string)
                env.passwords[host_string] = password
