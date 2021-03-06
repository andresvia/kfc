# -*- coding: utf-8 -*-
# seq

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from __future__ import unicode_literals

import re
import serverinfo
import os
import json
import time
import xlsxwriter
import tempfile
import codecs
import io
import socket

from fabric.api import (task, env, open_shell,
                        settings, run, hide, lcd,
                        runs_once, execute, put)
from fab import server
from fab import operations
from lib import util
from lib import unix

servers = server.Server(serverinfo.oses)
op = operations.Operations(servers.access_dict)
su = op.su

report = util.xlist()

### new generation ###


@task
@runs_once
def invoke_create_server_json():
    execute(create_server_json)
    serverinfo.server_info_cache.save()


###
### This function sets the time on the remote hosts the same as the time on
### the hosts running fabric.
###
### This function is useful on hosts where ntp is not installed or where
### misconfiguration of TZ makes ntpdate unusable.
###
@task
def set_date_as_local():
    su("echo")  # command executed initialize the connection
    t0 = time.time()
    su("echo")  # command executed to measure time correction
    t1 = time.time()
    correction = t1 - t0
    set_date = time.time() + correction
    set_date = time.localtime(set_date)
    exec_command = "date %02d%02d%02d%02d%4d.%02d" % (set_date.tm_mon,
                                                      set_date.tm_mday,
                                                      set_date.tm_hour,
                                                      set_date.tm_min,
                                                      set_date.tm_year,
                                                      set_date.tm_sec)
    su(exec_command)


### not perfect but useful for some tasks
@task
def shell():
    open_shell()


### not perfect but useful for some tasks
@task
def root_shell():
    old_remote_interrupt = env.remote_interrupt
    env.remote_interrupt = True
    su("sh")
    env.remote_innterrupt = old_remote_interrupt


### test if I can root
@task
def test_root():
    su("id")


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
    # future: guestinfo, serial, os_revision
    properties.sort()
    for prop in properties:
        get_function = globals()['get_' + prop]
        server_dict[prop] = get_function()
    return server_dict


### end new generation ###


### basic functions ###


def get_name():
    return re.split('[@:]', env.host_string)[1]


def get_os_type():
    os_type = _get_cached_result('os_type')
    if os_type is None:
        with settings(hide('running', 'stdout', 'debug')):
            os_type = run('uname')
        _save_cached_result('os_type', os_type)
    return(os_type)


def get_hostname():
    hostname = _get_cached_result('hostname')
    if hostname is None:
        with settings(hide('running', 'stdout', 'debug')):
            hostname = run('hostname')
        _save_cached_result('hostname', hostname)
    return(hostname)


def get_uname(param=' -a'):
    uname = _get_cached_result('uname%s' % param)
    if uname is None:
        with settings(hide('running', 'stdout', 'debug')):
            uname = run('uname%s' % param)
        _save_cached_result('uname%s' % param, uname)
    return(uname)


def get_virtinfo():
    virtinfo = _get_cached_result('virtinfo')
    if virtinfo is None:
        virtinfo_binary = _get_virtinfo_binary()
        if virtinfo_binary is not None:
            command_prefix = "command"
            virtinfo = su("echo @%s@ ; %s" % (command_prefix, virtinfo_binary))
            virtinfo = _get_command_output(virtinfo, command_prefix)
        _save_cached_result('virtinfo', virtinfo)
    return(virtinfo)


def get_ifaces():
    ifaces = _get_cached_result('ifaces')
    if ifaces is None:
        uname = get_os_type()
        if uname == "Linux":
            ifconfig = "/sbin/ifconfig"
        elif uname == "SunOS":
            ifconfig = "/sbin/ifconfig -a"
        elif uname == "HP-UX":
            ifconfig = """
#run ifconfig
for i in `/usr/sbin/lanscan -i | awk '{print $1}'`
do
  /usr/sbin/ifconfig $i 2>/dev/null
done
"""
        else:
            assert False
        with settings(hide('running', 'stdout', 'debug')):
            ifaces = run_string(ifconfig, interpreter='/bin/sh ')
        _save_cached_result('ifaces', ifaces)
    return ifaces

### end basic functions ###


### supporting functions ###


def _get_cached_result(key):
    cget = serverinfo.server_info_cache.cache_get
    cached_content = cget(key + '@' + env.host_string)
    if cached_content is not None:
        return cached_content.content
    else:
        return None


def _save_cached_result(key, content):
    cput = serverinfo.server_info_cache.cache_put
    return cput(key + '@' + env.host_string, content)


###
### su -, generates login output garbage, this function
### strip-out this garbage searching for the start of the commands execution
### if the su - command was prefixed with "@command_prefix@"
###
def _get_command_output(command_result, command_prefix):
    command_output_splitlines = []
    command_found = False
    for output_line in command_result.splitlines():
        if command_found:
            command_output_splitlines.append(output_line)
        if(output_line == "@%s@" % command_prefix):
            command_found = True
    ret = util.xstr('\n'.join(command_output_splitlines))
    ret.succeeded = command_result.succeeded
    return ret


def executable_found(list_of_execs):
    for exec_file in list_of_execs:
        result = run("test -x %s" % exec_file, warn_only=True)
        if result.succeeded:
            return exec_file
    return "echo No executable found."


def _get_virtinfo_binary():
    SunOS_virtinfo_binaries = []
    SunOS_virtinfo_binaries.append("/usr/sbin/virtinfo")
    Linux_virtinfo_binaries = []
    Linux_virtinfo_binaries.append("/usr/sbin/virt-what")
    virtinfo_binaries = locals()[get_os_type() + '_virtinfo_binaries']
    return executable_found(virtinfo_binaries)


###
### runs the string as a script can use a interpreter or
### can be run as_root
###
@task
def run_string(string, as_root=False, interpreter=''):
    sio = io.StringIO(string)
    return run_script(sio, as_root, interpreter)


###
### Runs a local script or anything that put can take, like a StringIO.
###
### If fails with "size mismatch in put!  0 != X" /tmp on remote host may have
### not enough free space.
###
@task
def run_script(script, as_root=False, interpreter=''):
    remote_script = run('mktemp')
    put(script, remote_script)
    run('chmod +x %s' % remote_script)
    if as_root == '1':
        runwith = su
    else:
        runwith = run
    r = runwith("%s%s%s" % (unix.unlang,
                            interpreter,
                            remote_script), warn_only=True)
    run("rm %s" % remote_script)
    return r


### end supporting functions ###


### reporting support functions ###


###
### Prints previously generated report in a tab separated values form
### by default, but you can change this behavior by invoking print_report
### with other values
###
@task
@runs_once
def print_report(header='1', sort='0', separator='\t', vseparator='\n'):
    print(gen_report(header, sort, separator, vseparator))
    serverinfo.server_info_cache.save()


###
### Generates by default a temp file
### you can change the default report_path to create the report in a diferent
### directory or with another report name.
###
@task
@runs_once
def save_report(header='1', sort='1', separator='\t', vseparator='\n',
                report_path=None, launch='0'):
    if report_path is None:
        report_path = tempfile.mktemp('.tsv')
    codecs.open(report_path,
                mode='w',
                encoding='utf-8').write(gen_report(header,
                                                   sort,
                                                   separator,
                                                   vseparator))
    if (launch == '1'):
        util.open_file(report_path)
    else:
        print("%s generated" % report_path)
    serverinfo.server_info_cache.save()


###
### Generates by default a temp xlsx file wich can be changed with report_path
###
@task
@runs_once
def xlsx_report(header='1', sort='1', report_path=None,
                launch='1'):
    if report_path is None:
        report_path = tempfile.mktemp('.xlsx')
    workbook = xlsxwriter.Workbook(report_path)
    worksheet = workbook.add_worksheet()
    col = 0
    row = 0
    bold = workbook.add_format({'bold': True})
    if sort == '1':
        report.sort()
    if header == '1':
        for column_title in report.header:
            worksheet.write(row, col, column_title, bold)
            col += 1
        col = 0
        row += 1
    for report_row in report:
        for report_cell in report_row:
            worksheet.write(row, col, report_cell)
            col += 1
        col = 0
        row += 1
    workbook.close()
    if (launch == '1'):
        util.open_file(report_path)
    else:
        print("%s generated" % report_path)
    serverinfo.server_info_cache.save()


###
### Function which do the heavy work of generating a report
###
def gen_report(header, sort, separator, vseparator):
    if (sort == '1'):
        report.sort()
    if header == '1':
        report.insert(0, report.header)
    sep = '\u21e5'  # tab
    vsep = '\u00b6'  # pilcrow
    for i in range(len(report)):
        for j in range(len(report[i])):
            # replace non-unix line terminations
            cell = report[i][j].replace('\r\n', '\n')
            cell = cell.replace('\n\r', '\n')
            cell = cell.replace('\r', '\n')
            cell = cell.replace(separator, sep)
            cell = cell.replace(vseparator, vsep)
            report[i][j] = cell
    return(vseparator.join([separator.join(x) for x in report]))


###
### Gets an splited array of ifconfig output of a variety of OSes
### and returns and splited array of /etc/hosts like lines
### this function checks with socket.gethostbyname wich of the address in the
### ifconfig input is the "main" interface of the host and builds host line
### according to this
###
def get_host_lines(hostname, iface, defaultdomain=''):
    iname = re.sub(':$', '', iface[0][0]).replace(':', '-')
    ips = []
    lines = []
    hosts_format = "%s %s %s %s %s"
    for line in iface[1:]:
        value = ' '.join(line[1:])
        if line[0] == "inet":
            ips.append((value.replace('addr:', '').split()[0], ''))
        elif line[0] == "inet6":
            ips.append((value.replace('addr:', '').split('/')[0], '-ipv6'))
    try:
        resolvedip = socket.gethostbyname(hostname)
    except:
        resolvedip = ''
    for (ip, ver) in ips:
        dn = "%s-%s%s" % (hostname, iname, ver)
        if ip == resolvedip:
            ifhost = hostname
        else:
            ifhost = ''
        if defaultdomain != '':
            fqdn = dn + defaultdomain
            if ifhost != '':
                fqifhost = ifhost + defaultdomain
            else:
                fqifhost = ''
        else:
            fqdn = ''
            fqifhost = ''
        line = hosts_format % (ip, ifhost, fqifhost, dn, fqdn)
        lines.append(line.split())
    return lines


### end reporting support functions ###


### report building functions ###

###
### These functions build the "report" variable with information which can be
### later print_report'd or save_report'd.
###
### For example:
###
### fab build_access_report \
###   save_report:separator=';':report_path=/tmp/host_strings.csv
###
### First build the report then save the report to /tmp/host_strings.csv
###

###
### Builds a report of access to the hosts. Can be used to generate a list
### of hosts for later use with another tools that understand host_string
### format. The unsafe version of the list includes the password, the function
### can be instructed to build the login access or the su access.
###
@task
def build_access_report(login='1', unsafe='0', servername='0'):
    server_object = servers.access_dict[env.host_string]

    unsafe_login_hoststring = server_object.host_string.unsafe
    unsafe_su_hoststring = server_object.su_host_string.unsafe
    login_hoststring = server_object.host_string
    su_hoststring = server_object.su_host_string

    no_header = False
    if not hasattr(report, 'header'):
        no_header = True

    report_row = []
    if no_header:
        report_header = []

    if servername == '1':
        if no_header:
            report_header.append('server_name')
        report_row.append(get_name())

    if no_header:
        report_header.append('host_string')

    if login == '1':
        if unsafe == '1':
            srvstr = unsafe_login_hoststring
        else:
            srvstr = login_hoststring
    else:
        if unsafe == '1':
            srvstr = unsafe_su_hoststring
        else:
            srvstr = su_hoststring
    report_row.append(srvstr)
    report.append(report_row)
    if no_header:
        report.header = report_header


###
### Builds a report of time and ntp configuration on the host. Can be used to
### check time configuration in a number of hosts, what is checked is:
### time where fabric runs, time on the remote host (both in ISO and epoch
### format), time diff between them,
### check how many ntpd process are running, check how many ntpd services are
### available, check how many ntpd services are enabled, check "server"
### parameter in ntp.conf file, check ntpdate <address> in root crontab.
###
### With this report you can plan what changes need to be done on which servers
### and check the time and ntp configuration on hosts.
###
@task
def build_ntp_report():
    if not hasattr(report, 'header'):
        report.header = ["hostname", "time ntp", "time srv", "epoch ntp",
                         "epoch srv", "diff", "ntpd running", "ntpd svc avail",
                         "ntpd svc enable", "conf", "cron conf"]

    with settings(hide('running', 'stdout', 'debug')):
        remote_time = run("%sdate" % unix.unlang)

    remote_time = re.sub("\s+[A-Z]{3}(-[0-9]{1,2})?\s*", " ", remote_time)

    remote_time = re.sub('\s+0([0-9]+)\s+', ' \\1 ', remote_time)
    remote_time = ' '.join(remote_time.split())
    local_time = time.asctime()
    remote_time_int = time.mktime(time.strptime(remote_time))
    local_time_int = time.mktime(time.strptime(local_time))
    remote_time_a = time.strftime("%a %b %d %H:%M:%S %Y",
                                  time.localtime(remote_time_int))
    remote_time_a = re.sub('\s+0([0-9]+)\s+', ' \\1 ', remote_time_a)
    assert remote_time == remote_time_a
    time_diff = remote_time_int - local_time_int
    os_type = get_os_type()
    with settings(hide('running', 'stdout', 'debug')):
        if run("uname -r") == "B.11.11":  # HP-UX 11.11 is a funky OS
            ntpd = run("ps -e | grep ntpd | wc -l")
        else:
            ntpd = run("pgrep ntpd | wc -l")
    ntp_conf = "None"
    cron_ntp_conf = "None"
    command_prefix = "command"
    with settings(hide('running', 'stdout', 'debug')):
        crontab = su("echo @%s@ ; crontab -l | grep ntpdate" % command_prefix,
                      warn_only=True)
    crontab = _get_command_output(crontab, command_prefix)
    if os_type == "Linux":
        with settings(hide('running', 'stdout', 'debug')):
            run("/sbin/chkconfig --list")
            ntpd_svc_n = run("/sbin/chkconfig --list|grep -i 'ntp'|wc -l")
            ntpd_svc = run("/sbin/chkconfig --list|"
                           "egrep -i 'ntp.*[234]:on'|wc -l")
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
                for j in range(6, len(line)):
                    if len(line[j]) >= 7 and line[j][0] != '-':
                        cron_ntp_srv.append(line[j])
    if len(cron_ntp_srv) == 0:
        cron_ntp_srv = ["None"]
    if ntp_conf != "None":
        ntp_conf = " ".join(ntp_srv)
    if crontab.succeeded:
        cron_ntp_conf = " ".join(cron_ntp_srv)
    report.append([get_name(), local_time, remote_time, str(local_time_int),
                  str(remote_time_int), str(time_diff), str(ntpd),
                  str(ntpd_svc_n), str(ntpd_svc), ntp_conf, cron_ntp_conf])


###
### Builds a report for uptime stats
###
@task
def build_uptime_report():
    if not hasattr(report, 'header'):
        report.header = ["hostname", "uptime"]

    with settings(hide('running', 'stdout', 'debug')):
        uptime = run("%suptime" % unix.unlang)

    uptime = uptime.split(',')
    if len(uptime) >= 6:
        days = uptime[0]
    else:
        days = "up 0 days"
    try:
        days = re.search("\s+up\s+([0-9]+)\s+day", days).groups()[0]
    except:
        days = "0"

    report.append([get_name(), days])


###
### Builds a /etc/hosts like file, use with save_report to update your hosts
### file, has added benefits like knowing all the interfaces of the servers
### and which interface is the "main" interface of the server, useful for
### greping information from hosts
###
@task
def build_hosts_file(defaultdomain=None):
    if not hasattr(report, 'header'):
        report.header = ["#ip-address", "hostname", "alias"]
    ifconfig = get_ifaces()
    ifaces = []
    iface = []
    for line in ifconfig.splitlines():
        linesplit = line.split()
        if len(line) > 0:
            if not re.match('\s', line[0]):
                if len(iface) == 0:
                    iface.append(linesplit)
                else:
                    ifaces.append(iface)
                    iface = []
                    iface.append(linesplit)
            else:
                iface.append(linesplit)
    if len(iface) != 0:
        ifaces.append(iface)
    if defaultdomain is None:
        defaultdomain = ''
    else:
        defaultdomain = "." + defaultdomain
    for iface in ifaces:
        report.extend(get_host_lines(get_name(), iface, defaultdomain))


### end report building functions ###

### file copy functions ###


###
### Dumb dir copy, we have no rsync on most servers and most unices dont't have
### cp -u option. This function do some stupid things, we are allowing only
### some inputs to avoid havok. mktemp -p on some HP-UX OSes does not create
### the directory, so this function will only work on Linux or SunOS so far.
###
### If fails with "size mismatch in put!  0 != X" /tmp on remote host may have
### not enough free space.
###
@task
def dumb_dir_copy(local_dir, remote_dir, delete_first=False,
                  as_root=False):
    remote_dir = re.sub('/+', '/', remote_dir.strip())
    if remote_dir in ['/', '/etc', '/var', '/usr', '/opt', '/sys',
                      '/tmp', '/proc', '/boot', '/home', '/dev', '/mnt']:
        print('I will not copy to that dir.')
        return
    if not remote_dir.startswith('/'):
        print('I will not copy to relative dirs.')
        return
    if remote_dir.count(' ') > 0:
        print("I can't copy to that dir.")
        return
    if remote_dir == '':
        print("I will not copy to no dir.")
        return
    uname = run("uname")
    if uname not in ["Linux", "SunOS"]:
        print("Only works on selected OSes.")
    remote_exists = run('test -d %s' % remote_dir, warn_only=True).succeeded
    if remote_exists:
        print('%s is a directory' % remote_dir)
    else:
        print("%s don't exist, exists as a file, or can't reach" % remote_dir)
    remote_created = False
    if as_root == '1':
        runme = su
    else:
        runme = run
    if not remote_exists:
        remote_created = runme("mkdir -p %s" % remote_dir,
                               warn_only=True).succeeded
        remote_exists = remote_created
    if remote_exists:
        with lcd(local_dir):
            put_dir = run('mktemp -d')
            put('%s%s%s' % (local_dir, os.sep, '*'),
                put_dir,
                mirror_local_mode=True)
            if delete_first == '1':
                runme("rm -rf %s/*" % remote_dir)  # this is stupid
            runme('cp -rpf %s%s%s %s' % (put_dir, '/', '*', remote_dir))
            run('rm -rf %s' % put_dir)
            if as_root == '1':
                su('chown -R root:root %s' % remote_dir)  # this is also stupid
    else:
        print("%s still can't create or reach" % remote_dir)

### end file copy functions ###
