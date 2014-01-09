# -*- coding: utf-8 -*-
# clases

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import re

from fabric.api import settings, hide, run, env, sudo


class Operations(object):

    def __init__(self, access_dict):
        self.access_dict = access_dict

    def su(self, su_exec, warn_only=False, use_shell=False):
        wo = warn_only
        with settings(hide('running', 'stdout', 'debug'), use_shell=use_shell,
                      warn_only=wo):
            uname = run("uname")
        su_command = self.access_dict[env.host_string].su_command
        if uname == "HP-UX":
            su_command = su_command.replace('su -', 'su')
        su_password = self.access_dict[env.host_string].su_password
        old_password = "%s" % env.passwords[env.host_string]
        env.passwords[env.host_string] = su_password
        r = None
        if (re.match("root@.*", env.host_string)):
            with settings(use_shell=use_shell, warn_only=wo):
                r = run(su_exec, warn_only=wo)
        else:
            with settings(sudo_prefix=su_command, sudo_prompt="Password: ",
                      use_shell=use_shell, warn_only=wo):
                r = sudo('"%s"' % su_exec.replace('"', '\\"'))
        env.passwords[env.host_string] = old_password
        return r
