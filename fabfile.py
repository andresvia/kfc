# -*- coding: utf-8 -*-
# seq

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import re
import serverinfo
import os
import json

from fabric.api import (task, env, open_shell,
                        settings, run, hide,
                        put, runs_once, execute, local)
from fab import server
from fab import operations

servers = server.Server(serverinfo.oses)
op = operations.Operations(servers.access_dict)
su = op.su


### new generation ###


@task
@runs_once
def invoke_create_server_json():
    execute(create_server_json)
    serverinfo.server_info_cache.save()


def create_server_json():
    server_dict = create_server_dict()
    filename = 'json' + os.sep + server_dict['name'] + '.json'
    fd = open(filename, 'w')
    fd.write(json.dumps(server_dict,
             sort_keys=True,
             indent=4,
             separators=(',', ': ')))
    fd.write('\n')
    fd.close()


def create_server_dict():
    server_dict = {}
    properties = ['name', 'os_type', 'hostname', 'uname', 'virtinfo']
    properties.sort()
    for prop in properties:
        get_function = globals()['get_' + prop]
        server_dict[prop] = get_function()
    #server_json['serial'] = get_serial()
    return server_dict


### end new generation ###


### basic functions ###


def get_name():
    return re.split('[@:]', env.host_string)[1]


def get_os_type():
    os_type = get_cached_result('os_type')
    if os_type is None:
        with settings(hide('running', 'stdout', 'debug')):
            os_type = run('uname')
        save_cached_result('os_type', os_type)
    return(os_type)


def get_hostname():
    hostname = get_cached_result('hostname')
    if hostname is None:
        with settings(hide('running', 'stdout', 'debug')):
            hostname = run('hostname')
        save_cached_result('hostname', hostname)
    return(hostname)


def get_uname():
    uname = get_cached_result('uname')
    if uname is None:
        with settings(hide('running', 'stdout', 'debug')):
            uname = run('uname -a')
        save_cached_result('uname', uname)
    return(uname)


def get_virtinfo():
    virtinfo = get_cached_result('virtinfo')
    if virtinfo is None:
        virtinfo_binary = get_virtinfo_binary()
        if virtinfo_binary is not None:
            command_prefix = "command"
            virtinfo = su("echo @%s@ ; %s" % (command_prefix, virtinfo_binary))
            virtinfo = get_command_output(virtinfo, command_prefix)
        save_cached_result('virtinfo', virtinfo)
    return(virtinfo)


### def get_guestinfo():


### end basic functions ###


### supporting functions ###


def get_cached_result(key):
    cget = serverinfo.server_info_cache.cache_get
    cached_content = cget(key + '@' + env.host_string)
    if cached_content is not None:
        return cached_content.content
    else:
        return None


def save_cached_result(key, content):
    cput = serverinfo.server_info_cache.cache_put
    return cput(key + '@' + env.host_string, content)


###
### Running a command with su, generates login output garbage, this function
### strip-out this garbage searching for the start of the commands execution
### if the su command was prefixed with "@command_prefix"
###
def get_command_output(command_result, command_prefix):
    command_output_splitlines = []
    command_found = False
    for output_line in command_result.splitlines():
        if command_found:
            command_output_splitlines.append(output_line)
        if(output_line == "@%s@" % command_prefix):
            command_found = True
    return '\n'.join(command_output_splitlines)


def executable_found(list_of_execs):
    for exec_file in list_of_execs:
        result = run("test -x %s" % exec_file, warn_only=True)
        if result.succeeded:
            return exec_file
    return "echo No executable found."


def get_virtinfo_binary():
    SunOS_virtinfo_binaries = []
    SunOS_virtinfo_binaries.append("/usr/sbin/virtinfo")
    Linux_virtinfo_binaries = []
    Linux_virtinfo_binaries.append("/usr/sbin/virt-what")
    virtinfo_binaries = locals()[get_os_type() + '_virtinfo_binaries']
    return executable_found(virtinfo_binaries)


### end supporting functions ###


@task
def print_access():
    print("%s %s" % (servers.access_dict[env.host_string].host_string.unsafe,
                     servers.access_dict[env.host_string].host))
    print("%s %s" % (servers.access_dict[env.host_string].su_host_string.unsafe,
                     servers.access_dict[env.host_string].host))


@task
def get_hba_info():
    su("/usr/sbin/fcinfo hba-port", warn_only=True)


@task
def get_uptime_info():
    su("echo @@uptime@@ ; uptime")


@task
def get_uname_info():
    su("echo @@uname@@ ; uname -a")


@task
def shell():
    open_shell()


@task
def get_pass_param():
    admin_users = ["admin", "Root", "root"]
    admin_users = get_existing_users(admin_users)
    with settings(hide('stderr'), hide('stdout'), hide("running")):
        uname = run("uname -a")
    if re.match(".*SunOS.*", uname):
        get_pass_param_solaris(admin_users)
    if re.match(".*Linux.*", uname):
        get_pass_param_linux(admin_users)
    if re.match(".*HP-UX.*", uname):
        get_pass_param_hpux(admin_users)


def get_existing_users(user_list):
    existing_users = []
    for user in user_list:
        with settings(hide('stderr', 'stdout', 'running', 'warnings'),
                      warn_only=True):
            idux = run("id %s" % user)
            if idux.succeeded:
                existing_users.append(user)
    return existing_users


def get_pass_param_solaris(admin_users):
    password_age_commands = ""
    for admin_user in admin_users:
        password_age_commands += " passwd -s %s ; " % admin_user
    su("egrep "
       "'^(MAXWEEKS|PASSLENGTH|HISTORY|RETRIES|LOCK_AFTER_RETRIES)' "
       "/etc/default/passwd "
       "/etc/default/login "
       "/etc/security/policy.conf ; "
       "crontab -l | grep passwd ; "
       "%s" % password_age_commands)


def get_pass_param_hpux(admin_users):
    password_age_commands = ""
    for admin_user in admin_users:
        password_age_commands += " passwd -s %s ; " % admin_user
    su("egrep "
       "'^(MIN_PASSWORD_LENGTH|PASSWORD_HISTORY_DEPTH|PASSWORD_MAXDAYS|"
       "AUTH_MAXTRIES)|u_life|u_maxtries' "
       "/etc/default/security "
       "/tcb/files/auth/system/default 2>/dev/null ; "
       "crontab -l | egrep 'modprpw|userdbset' ; "
       "%s" % password_age_commands)


def get_pass_param_linux(admin_users):
    password_age_commands = ""
    for admin_user in admin_users:
        password_age_commands += " echo chage %s ; " % admin_user
        password_age_commands += " chage -l %s ; " % admin_user
    su("egrep "
       "'^(PASS_MAX_DAYS|PASS_MIN_LEN)' /etc/login.defs ; "
       "egrep -n "
       "'pam_tally.so|remember|pam_faillock.so' "
       "/etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null ; "
       "crontab -l | egrep 'faillog|faillock' ; "
       "%s" % password_age_commands)


@task
def get_format():
    su("format < /dev/null ; true")


@task
def get_multipathll():
    su("multipath -ll ; true")


@task
def root_shell():
    old_remote_interrupt = env.remote_interrupt
    env.remote_interrupt = True
    su("sh")
    env.remote_innterrupt = old_remote_interrupt


@task
def copy_scripts():
    put("scripts/change_passwd_params_solaris.sh", "/tmp", mode=0x755)


@task
def set_rackt_value(param_name):
    os_family = get_os_family()
    if (param_name == "RAM (MB)"):
        if (os_family == "Linux"):
            with settings(hide('stderr'), hide('stdout'), hide("running")):
                total_mem = run("free -m")
            total_mem = total_mem.splitlines()[1].split()[1]
    print(total_mem)


@task
def create_server_yaml():
    hostname = run("hostname")
    dmidecode = su("dmidecode ; true")
    productname = ""
    serialnumber = ""
    for i in dmidecode.splitlines():
        a = i.split()
        if len(a) >= 2:
            if a[0] == "Product" and a[1] == "Name:" and productname == "":
                productname = " ".join(a[2:])
            if a[0] == "Serial" and a[1] == "Number:" and serialnumber == "":
                serialnumber = " ".join(a[2:])
    operatingsystem = run("cat /etc/redhat-release")
    yaml = open("yamls" + os.sep + hostname + ".yaml", "w")
    yaml.write("--- " + hostname + "\n")
    yaml.write("name: " + hostname + "\n")
    yaml.write("parameters:\n")
    yaml.write("  fqdn: " + hostname + "\n")
    yaml.write("  productname: " + productname + "\n")
    yaml.write("  serialnumber: " + serialnumber + "\n")
    yaml.write("  uuid:\n")
    yaml.write("  operatingsystem: " + operatingsystem + "\n")
    yaml.write("  operatingsystemrelease:\n")
    yaml.write("  hypervisor: No\n")
    yaml.close()


def get_os_family():
    with settings(hide('stderr'), hide('stdout'), hide("running")):
        uname = run("uname")
    if re.match(".*SunOS.*", uname):
        os_family = "SunOS"
    elif re.match(".*Linux.*", uname):
        os_family = "Linux"
    elif re.match(".*HP-UX.*", uname):
        os_family = "HP-UX"
    else:
        os_family = "Unknown"
    return os_family


@task
def revision():
    print("@revision@")
    run("cat /etc/redhat-release")


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


@task
def get_virtinfo_():
    zones = su("echo @zoneadm@;/usr/sbin/zoneadm list -vc", warn_only=True)
    virtinfo = su("echo @virtinfo@;/usr/sbin/virtinfo", warn_only=True)
    ldoms = su("echo @ldm@;/usr/sbin/ldm list", warn_only=True)

    zones_splitlines = []
    command_found = False
    for zoneadm_line in zones.splitlines():
        if command_found:
            zones_splitlines.append(zoneadm_line)
        if(zoneadm_line == "@zoneadm@"):
            command_found = True

    result_zones = []
    if zones.succeeded:
        for zone in zones_splitlines:
            zone = zone.split()
            if len(zone) >= 2:
                if(is_number(zone[0])):
                    result_zones.append(zone[1])

    virtinfo_splitlines = []
    command_found = False
    for virtinfo_line in virtinfo.splitlines():
        if command_found:
            virtinfo_splitlines.append(virtinfo_line)
        if(virtinfo_line == "@virtinfo@"):
            command_found = True

    result_virtinfo = ""

    if virtinfo.succeeded:
        result_virtinfo = " ".join(virtinfo_splitlines)

    ldm_splitlines = []
    command_found = False
    for ldm_line in ldoms.splitlines():
        if command_found:
            ldm_splitlines.append(ldm_line)
        if(ldm_line == "@ldm@"):
            command_found = True

    result_ldm = []
    if ldoms.succeeded:
        for ldm in ldm_splitlines[1:]:
            if len(ldm.split()) >= 1:
                result_ldm.append(ldm.split()[0])

    print("virtinfo:%s:%s:%s:%s" % (env.host,
                                    ", ".join(result_zones).replace(":", ""),
                                    result_virtinfo.replace(":", ""),
                                    ", ".join(result_ldm).replace(":", "")))




#def get_serial():

import time
import sys

all_dates = []

all_dates.append(";".join(["hostname", "hora ntp", "hora srv", "epoch ntp",
                 "epoch srv", "diff", "ntpd running", "ntpd svc av",
                 "ntpd svc en", "conf", "cron conf"]))

@task
def get_dates():
    with settings(hide('running', 'stdout', 'debug')):
        remote_time = run("LC_MESSAGES=C;export LC_MESSAGES;LC_ALL=C;export LC_ALL;LANG=C;export LANG;date")
    remote_time = remote_time.replace(' COT', '')
    remote_time = remote_time.replace(' GMT-5', '')
    remote_time = remote_time.replace(' SAT', '')
    local_time = time.asctime()
    remote_time_int = time.mktime(time.strptime(remote_time))
    local_time_int = time.mktime(time.strptime(local_time))
    remote_time_a = time.strftime("%a %b %d %H:%M:%S %Y",time.localtime(remote_time_int))
    if (remote_time != remote_time_a):
        print("Algo malo paso")
        sys.exit(1)
    time_diff = remote_time_int - local_time_int
    os_type = get_os_type()
    with settings(hide('running', 'stdout', 'debug')):
        ntpd = run("pgrep ntpd | wc -l")
    ntp_conf = "None"
    cron_ntp_conf = "None"
    crontab = su("crontab -l | grep ntpdate", warn_only=True)
    if os_type == "Linux":
        with settings(hide('running', 'stdout', 'debug')):
            run("/sbin/chkconfig --list")
            ntpd_svc_n = run("/sbin/chkconfig --list|grep -i 'ntp'|wc -l")
            ntpd_svc = run("/sbin/chkconfig --list|egrep -i 'ntp.*[234]:on'|wc -l")
            if run("test -f /etc/ntp.conf", warn_only=True).succeeded:
                ntp_conf = run("cat /etc/ntp.conf")
    elif os_type == "SunOS":
        with settings(hide('running', 'stdout', 'debug')):
            run("svcs")
            ntpd_svc_n = run("svcs -a | grep -i 'ntp' | wc -l")
            ntpd_svc = run("svcs -a | egrep -i 'online.*ntp:default' | wc -l")
            if run("test -f /etc/inet/ntp.conf", warn_only=True).succeeded:
                ntp_conf = run("cat /etc/inet/ntp.conf")
    elif os_type == "HP-UX":
        with settings(hide('running', 'stdout', 'debug')):
            ntpd_svc_n = run("test -f /sbin/init.d/xntpd && echo 1 || echo 0")
            ntpd_svc = run("test -x /sbin/init.d/xntpd && echo 1 || echo 0")
            if run("test -f /etc/ntp.conf", warn_only=True).succeeded:
                ntp_conf = run("cat /etc/ntp.conf")
    ntp_srv = []
    cron_ntp_srv = []
    for line in ntp_conf.splitlines():
        line = line.split()
        if len(line) >= 2:
            if line[0][0] == "#":
                continue
            elif line[0] == "server":
                ntp_srv.append(line[1])
    for line in crontab.splitlines():
        line = line.split()
        if len(line) >= 7:
            if line[0][0] == "#":
                continue
            else:
                for j in range(6,len(line)):
                    if len(line[j]) >= 7 and line[j][0] != '-':
                        cron_ntp_srv.append(line[j])
    if ntp_conf != "None":
        ntp_conf = " ".join(ntp_srv)
    if crontab.succeeded:
        cron_ntp_conf = " ".join(cron_ntp_srv)
    all_dates.append(";".join([get_name(), local_time, remote_time,
                               str(local_time_int), str(remote_time_int), str(time_diff),
                               str(ntpd), str(ntpd_svc_n), str(ntpd_svc),
                               ntp_conf, cron_ntp_conf]))

@task
@runs_once
def print_dates():
   for date in all_dates:
       print(date)

