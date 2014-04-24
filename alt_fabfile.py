# -*- coding: utf-8 -*-
# seq

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from __future__ import unicode_literals

### assorted,
### un-organized,
### un-portable &
### un-documented
### one-shot ugly functions and hacks
### to do fast work and requirements
### that have no place in fabfile.py

exec(compile(open('fabfile.py').read(), 'fabfile.py', 'exec'))

# to avoid error reporting in IDEs
#lint:disable
su = su
task = task
settings = settings
hide = hide
run = run
re = re
os = os
get_name = get_name
_get_command_output = _get_command_output
report = report
env = env
serverinfo = serverinfo
unix = unix
util = util
io = io
run_string = run_string
get_uname = get_uname
get_ifaces = get_ifaces
socket = socket
put = put
#lint:enable

from fabric.api import get, local
from fabric.state import connections


###
### Building a not so fancy report
### (not like xlsx_report)
###
@task
def get_pass_param():
    admin_users = ["admin", "Root", "root"]
    admin_users = _get_existing_users(admin_users)
    with settings(hide('stderr'), hide('stdout'), hide("running")):
        uname = run("uname -a")
    if re.match(".*SunOS.*", uname):
        _get_pass_param_solaris(admin_users)
    if re.match(".*Linux.*", uname):
        _get_pass_param_linux(admin_users)
    if re.match(".*HP-UX.*", uname):
        _get_pass_param_hpux(admin_users)


###
### Return a list of users which exists from the input list
###
def _get_existing_users(user_list):
    existing_users = []
    for user in user_list:
        with settings(hide('stderr', 'stdout', 'running', 'warnings'),
                      warn_only=True):
            idux = run("id %s" % user)
            if idux.succeeded:
                existing_users.append(user)
    return existing_users


###
### Get password parameters for some users
###
def _get_pass_param_solaris(admin_users):
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


###
### Get password parameters for some users
###
def _get_pass_param_hpux(admin_users):
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


###
### Get password parameters for some users
###
def _get_pass_param_linux(admin_users):
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


###
### Get format info
###
@task
def _get_format():
    su("format < /dev/null ; true")


###
### Get multipath info
###
@task
def _get_multipathll():
    su("multipath -ll ; true")


###
### Trying to feed rackatables with KFC
###
@task
def set_rackt_value(param_name):
    uname = run('uname')
    if (param_name == "RAM (MB)"):
        if (uname == "Linux"):
            with settings(hide('stderr'), hide('stdout'), hide("running")):
                total_mem = run("free -m")
            total_mem = total_mem.splitlines()[1].split()[1]
    print(total_mem)


###
### Trying to build server metadata
###
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


###
### Get RHEL release info
###
@task
def revision():
    print("@revision@")
    run("cat /etc/redhat-release")


###
### Trying to build a report for Zones and LDOMs
###
@task
def old_get_virtinfo():
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
                if(util.is_number(zone[0])):
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


###
### Finding "core" files
###
@task
def find_core():
    run("date")
    su("time find / \! "
       "-local "
       "-prune -o "
       "\( -name core -a -type f \) "
       "-exec ls -lh '{}' \; | tee")
    run("date")


###
### Finding HBA info on Solaris
###
@task
def find_hbas_solaris():
    name = get_name()
    result = su("/usr/sbin/fcinfo hba-port", warn_only=True)
    if result.succeeded:
        f = open("/tmp/hbas/%s.log" % name, "w")
        f.write(result)
        f.close()


###
### Finding HBA info on Linux
###
@task
def find_hbas_linux():
    command_prefix = "command"

    localscript = """
for i in /sys/class/{fc_host,scsi_host}/*/*
do
  echo -n $i';'
  a=$(cat -v "$i" 2>/dev/null) && echo $a || echo
done |
awk -F'/' '{for(i=5;i<=NF;i++){printf("%s;",$i)}printf("\\n")}' |
sort -u
"""

    f = open("/tmp/.kfc_find_hbas_linux", "w")
    f.write(localscript)
    f.close()

    name = get_name()

    script = run("mktemp")

    put("/tmp/.kfc_find_hbas_linux", script)

    result = su("echo @%s@ ; bash %s" % (command_prefix, script))
    result = _get_command_output(result, command_prefix)

    run("rm %s" % script)

    f = open("/tmp/hbas/%s" % name, "w")
    f.write(result)
    f.close()


###
### A report for Zones and LDOMs
###
@task
def solaris_virtinfo():
    report.header = ['hostname', 'virtinfo']
    command_prefix = "command"

    localscript = """

[ -e /usr/sbin/zoneadm ] && /usr/sbin/zoneadm list -v |
awk 'BEGIN{printf("Zones: ")}NR>=2{printf("%s ", $2)}END{printf("\\n")}'

[ -e /usr/sbin/virtinfo ] && echo "virtinfo: $(/usr/sbin/virtinfo)"

[ -e /usr/sbin/ldm ] && /usr/sbin/ldm list |
awk 'BEGIN{printf("LDOMS: ")}NR>=2{printf("%s ", $1)}END{printf("\\n")}'
"""

    f = open("/tmp/.kfc_solaris_virtinfo", "w")
    f.write(localscript)
    f.close()

    script = run("mktemp")

    put("/tmp/.kfc_solaris_virtinfo", script)

    result = su("echo @%s@ ; bash %s | tee" % (command_prefix, script))
    result = _get_command_output(result, command_prefix)

    run("rm %s" % script)

    #f = open("/tmp/hbas/%s" % name, "w")
    #f.write(result)
    #f.close()
    #result = result.replace('\n', '\\n').replace('\t', '\\t')
    report.append([get_name(), result])


###
### Another report for memory
###
@task
def solaris_meminfo():
    report.header = ['hostname', 'cpuused', 'memused',
                     'cores', 'memtotal', 'date']
    command_prefix = "command"

    localscript = """

prstat -t 1 1 < /dev/null | awk '{print $5}' |
tr -d '%' | awk '{S=S+$0}END{print S}'
psrinfo | wc -l
prstat -t 1 1 < /dev/null  | awk '{print $NF}' |
tr -d '%' | awk '{S=S+$0;A=$0}END{print S-A}'
prtconf -v 2>/dev/null | grep -i 'Memory size'
date

"""

    f = open("/tmp/.kfc_solaris_meminfo", "w")
    f.write(localscript)
    f.close()

    script = run("mktemp")

    put("/tmp/.kfc_solaris_meminfo", script)

    result = su("echo @%s@ ; bash %s | tee" % (command_prefix, script))
    result = _get_command_output(result, command_prefix)

    run("rm %s" % script)

    cpuused = result.splitlines()[2]
    memused = result.splitlines()[0]
    cores = result.splitlines()[1]
    memtotal = result.splitlines()[3]
    date = result.splitlines()[4]
    report.append([get_name(), cpuused, memused, cores, memtotal, date])


###
### A report for mpio versions
###
@task
def solaris_mpver():
    report.header = ['hostname', 'mpver', 'mppaths']
    command_prefix = "command"

    localscript = """

echo -n 'version mapthadm: ' ; mpathadm -V |grep -i version
echo -n "number of paths: " ; mpathadm list lu |
grep 'Operational Path Count:' | sort -ur | head -1

"""

    f = open("/tmp/.kfc_solaris_mpver", "w")
    f.write(localscript)
    f.close()

    script = run("mktemp")

    put("/tmp/.kfc_solaris_mpver", script)

    result = su("echo @%s@ ; bash %s | tee" % (command_prefix, script))
    result = _get_command_output(result, command_prefix)

    run("rm %s" % script)

    mpver = result.splitlines()[0]
    mppaths = result.splitlines()[1]
    report.append([get_name(), mpver, mppaths])


###
### A report for versions of volume managers (ZFS, SVM)
###
@task
def solaris_volver():
    report.header = ['hostname', 'ver SUNWvolr svm',
                     'ver SUNWzfskr zfs', 'ver SUNWmpapir mpio']
    command_prefix = "command"

    localscript = """

echo -n '1: ' ; pkginfo -l SUNWvolr | grep -i ver
echo -n "2: " ; pkginfo -l SUNWzfskr | grep -i version
echo -n '3: ' ; pkginfo -l SUNWmpapir  | grep -i version

"""

    f = open("/tmp/.kfc_solaris_mpver", "w")
    f.write(localscript)
    f.close()

    script = run("mktemp")

    put("/tmp/.kfc_solaris_mpver", script)

    result = su("echo @%s@ ; bash %s | tee" % (command_prefix, script))
    result = _get_command_output(result, command_prefix)

    run("rm %s" % script)

    svmver = result.splitlines()[0]
    zfsver = result.splitlines()[1]
    mpiover = result.splitlines()[2]
    report.append([get_name(), svmver, zfsver, mpiover])


###
### A report for versions of volume managers (LVM)
###
@task
def linux_volver():
    report.header = ['hostname', 'device-mapper-multipath',
                     'lvm2', 'e2fsprogs-libs']
    command_prefix = "command"

    localscript = """

rpm -q -a | egrep '^device-mapper-multipath-' | head -n1 |
awk 'BEGIN{printf("")}{print}'
rpm -q -a | egrep '^lvm2-' | head -n1 | awk 'BEGIN{printf("")}{print}'
rpm -q -a | egrep '^e2fsprogs-libs-' | head -n1 | awk 'BEGIN{printf("")}{print}'

"""

    f = open("/tmp/.kfc_solaris_mpver", "w")
    f.write(localscript)
    f.close()

    script = run("mktemp")

    put("/tmp/.kfc_solaris_mpver", script)

    result = su("echo @%s@ ; bash %s | tee" % (command_prefix, script))
    result = _get_command_output(result, command_prefix)

    run("rm %s" % script)

    try:
        svmver = result.splitlines()[0]
    except:
        svmver = ""
    try:
        zfsver = result.splitlines()[1]
    except:
        zfsver = ""
    try:
        mpiover = result.splitlines()[2]
    except:
        mpiover = ""
    report.append([get_name(), svmver, zfsver, mpiover])


###
### A random report
###
@task
def build_solaris_report():
    report.header = ['hostname',
                     'echo ::memstat|mdb -k',
                     "echo ::memstat|mdb -k|grep Anon|awk '{print \\$NF}'",
                     "prtdiag|egrep -i 'mem.*size'",
                     'dladm show-link',
                     "fcinfo hba-port|egrep 'HBA Port'",
                     "fcinfo hba-port|egrep Manufacturer|sort -u",
                     "virtinfo",
                     "ldm list|/usr/sfw/bin/ggrep -o primary",
                     "zoneadm list|grep global",
                     "ifconfig -a"]
    command_prefix = "command"
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[1]))
    memstat = _get_command_output(result, command_prefix)
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[2]))
    memanon = _get_command_output(result, command_prefix)
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[3]))
    memsize = _get_command_output(result, command_prefix)
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[4]))
    links = _get_command_output(result, command_prefix)
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[5]))
    hbas = _get_command_output(result, command_prefix)
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[6]))
    hbamanu = _get_command_output(result, command_prefix)
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[7]))
    virtinfo = _get_command_output(result, command_prefix)
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[8]))
    ldmlist = _get_command_output(result, command_prefix)
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[9]))
    zonelist = _get_command_output(result, command_prefix)
    result = su("echo @%s@;%s|tee" % (command_prefix, report.header[10]))
    ifconfig = _get_command_output(result, command_prefix)
    report.append([get_name(),
                  memstat,
                  memanon,
                  memsize,
                  links,
                  hbas,
                  hbamanu,
                  virtinfo,
                  ldmlist,
                  zonelist,
                  ifconfig])


###
### A report for counting logical processors
###
@task
def build_logic_core_count_report():
    if not hasattr(report, 'header'):
        report.header = ["hostname", "logic cores"]

    with settings(hide('running', 'stdout', 'debug')):
        uname = run('uname')
        if uname == "Linux":
            cores = run("egrep -c '^processor[[:space:]]*:[[:space:]]+' "
                        "/proc/cpuinfo")
        elif uname == "SunOS":
            cores = run("/usr/sbin/psrinfo | wc -l | tee")
    cores = str(int(cores))
    report.append([get_name(), cores])


###
### A report for memory used with no cache
###
@task
def build_current_memory_usage():
    if not hasattr(report, 'header'):
        report.header = ["hostname", "mem usage"]
    with settings(hide('running', 'stdout', 'debug')):
        uname = run('uname')
        if uname == "Linux":
            curmem = run("%sfree | awk 'NR==3{print $3}'" % unix.unlang)
            totmem = run("%sfree | awk 'NR==2{print $2}'" % unix.unlang)
            curmem = int(curmem) / int(totmem)
        elif uname == "SunOS":
            curmem = run("%sprstat -t 1 1 < /dev/null |" % unix.unlang
                         + "tr -d '%' |"
                         "awk '{M=M+$5}END{print M}'")
            curmem = float(curmem) / 100
            if curmem > 1:
                print("%s Memory overhead" % get_name())
                mdb = su("echo ::memstat | mdb -k")
                for line in mdb.splitlines():
                    line = line.split()
                    try:
                        if line[0] == "Anon":
                            curmem = line[3].replace("%", "")
                            curmem = float(curmem) / 100
                    except:
                        pass
    report.append([get_name(), curmem])


###
### A report for every mounted filesystem
###
@task
def build_df_report():
    uname = run('uname')
    if uname == "Linux":
        runcmd = "%sdf -kP" % unix.unlang
    elif uname == "HP-UX":
        runcmd = "%sdf -kP" % unix.unlang
    elif uname == "SunOS":
        runcmd = "%sdf -k|tr" % unix.unlang
    output = run(runcmd)
    for line in output.splitlines():
        line = line.split()
        report.append([get_name()] + line)


###
### A report for every task on root crontab
###
@task
def build_root_crontab_report():
    command_prefix = "command"
    output = su('echo @%s@;%scrontab -l' % (command_prefix, unix.unlang))
    output = _get_command_output(output, command_prefix)
    for line in output.splitlines():
        line = line.split()
        if len(line) > 0 and line[0].startswith('@'):
                report.append([get_name()] +
                              line[0:1] +
                              [''] * 4 +
                              [' '.join(line[1:])])
        if len(line) > 0 and not line[0].startswith('#'):
                report.append([get_name()] +
                              line[0:5] +
                              [' '.join(line[5:])])


###
### building some "security" report
###
@task
def security_checks_solaris():
    if not hasattr(report, 'header'):
        report.header = ["hostname", "0.1 kernel version",
                         "0.2a sshd LogLevel (verbose)",
                         "0.2b sshd Protocol (2)",
                         "0.2c sshd X11Forwarding (no)",
                         "0.2d sshd IgnoreRhosts (yes)",
                         "0.2e sshd RhostsAuthentication (no)",
                         "0.2f sshd RhostsRSAAuthentication (no)",
                         "0.2g sshd PermitRootLogin (no)",
                         "0.2h sshd PermitEmptyPasswords (no)",
                         "0.2i sshd Banner",
                         "0.2j sshd_config priv",
                         "0.2k ssh_config priv",
                         "1.1 Print Service (disabled)",
                         "1.2 Telnet Service (disabled)",
                         "1.3 Finger Service (disabled)",
                         "1.4a FTP Service (disabled)",
                         "1.4b TFTP/UDP6 Service (disabled)",
                         "1.4c inetd/tftp (disabled)",
                         "1.4d Deny FTP users",
                         "1.5a Echo datagram Service (disabled)",
                         "1.5b Echo stream Service (disabled)",
                         "1.6a Discard datagram Service (disabled)",
                         "1.6b Discard stream Service (disabled)",
                         "1.7a Chargen datagram Service (disabled)",
                         "1.7b Chargen stream Service (disabled)",
                         "1.8a Daytime datagram Service (disabled)",
                         "1.8b Daytime stream Service (disabled)",
                         "4.3 Password expire (60)",
                         "4.4 Password history (24)",
                         "4.5a Max retries (6)",
                         "4.5b Lock after retries (yes)",
                         "4.8a + Entries on passwd (0)",
                         "4.8b + Entries on group (0)", ]
    p0_2a = "INFO"
    p0_2b = "2"
    p0_2c = "no"
    p0_2d = "yes"
    p0_2e = "no"
    p0_2f = "no"
    p0_2g = "yes"
    p0_2h = "no"
    p0_2i = "none"
    p0_2j = ""
    p0_2k = ""
    with settings(hide('stderr'), hide('stdout'), hide("running")):
        # p0_1 = run("pkginfo -l SUNWckr | grep 'VERSION' | cut -d: -f2-")
        p0_1 = run("uname -v")
        sshd_config = run('cat /etc/ssh/sshd_config')
        inetd_config = run('cat /etc/inetd.conf')
        svcs_a = run('svcs -Ha -o state,fmri')
        inetd_services = []
        services = {}
        ftpd_users = run('cat /etc/ftpd/ftpusers || echo')
        p0_2j = run("ls -l /etc/ssh/sshd_config | awk '{print $1, $3, $4}'")
        p0_2k = run("ls -l /etc/ssh/ssh_config | awk '{print $1, $3, $4}'")
        p4_3 = run("egrep '^MAXWEEKS=' /etc/default/passwd || echo no")
        p4_4 = run("egrep '^HISTORY=' /etc/default/passwd || echo no")
        p4_5a = run("egrep '^RETRIES=' /etc/default/login || echo no")
        p4_5b = run("egrep '^LOCK_AFTER_RETRIES=' /etc/security/policy.conf ||"
                    "echo no")
        p4_8a = run("egrep '^[\t ]*\+[\t ]*:' /etc/passwd | wc -l")
        p4_8b = run("egrep '^[\t ]*\+[\t ]*:' /etc/group | wc -l")
        uname_r = run('uname -r')
    for line in sshd_config.splitlines():
        line = line.split()
        if len(line) > 1:
            if line[0].upper() == 'LOGLEVEL':
                p0_2a = line[1]
            elif line[0].upper() == 'PROTOCOL':
                p0_2b = line[1]
            elif line[0].upper() == 'X11FORWARDING':
                p0_2c = line[1]
            elif line[0].upper() == 'IGNORERHOSTS':
                p0_2d = line[1]
            elif line[0].upper() == 'RHOSTSAUTHENTICATION':
                p0_2e = line[1]
            elif line[0].upper() == 'RHOSTSRSAAUTHENTICATION':
                p0_2f = line[1]
            elif line[0].upper() == 'PERMITROOTLOGIN':
                p0_2g = line[1]
            elif line[0].upper() == 'PERMITEMPTYPASSWORDS':
                p0_2h = line[1]
            elif line[0].upper() == 'BANNER':
                p0_2i = line[1]
    for line in inetd_config.splitlines():
        if re.match("^\s*[^#]", line):
            line = line.split()
            if len(line) > 1:
                inetd_services.append(line[0])
    for line in svcs_a.splitlines():
        line = line.split()
        services[line[1]] = line[0]
    try:
        if uname_r == "5.10":
            p1_1 = services['svc:/application/print/server:default']
        elif uname_r == "5.11":
            p1_1 = services['svc:/application/cups/in-lpd:default']
    except:
        p1_1 = "uninstalled"
    try:
        p1_2 = services['svc:/network/telnet:default']
    except:
        p1_2 = "uninstalled"
    try:
        p1_3 = services['svc:/network/finger:default']
    except:
        p1_3 = "uninstalled"
    try:
        p1_4 = services['svc:/network/inetd:default']
    except:
        p1_4 = "uninstalled"
    try:
        p1_4a = services['svc:/network/ftp:default']
    except:
        p1_4a = "uninstalled"
    try:
        p1_4b = services['svc:/network/tftp/udp6:default']
    except:
        p1_4b = "uninstalled"
    if p1_4 == 'online':
        if 'tftp' in inetd_services:
            p1_4c = 'enabled'
        else:
            p1_4c = 'disabled'
    else:
        p1_4c = 'inetd disabled'
    if p1_4a == "online":
        p1_4d = []
        for line in ftpd_users.splitlines():
            if re.match("^\s*[^#]", line):
                line = line.split()
                if len(line) > 0:
                    p1_4d.append(line[0])
        p1_4d = ' '.join(p1_4d)
    else:
        p1_4d = 'ftpd disabled'
    try:
        p1_5a = services['svc:/network/echo:dgram']
    except:
        p1_5a = "uninstalled"
    try:
        p1_5b = services['svc:/network/echo:stream']
    except:
        p1_5b = "uninstalled"

    try:
        p1_6a = services['svc:/network/discard:dgram']
    except:
        p1_6a = "uninstalled"
    try:
        p1_6b = services['svc:/network/discard:stream']
    except:
        p1_6b = "uninstalled"

    try:
        p1_7a = services['svc:/network/chargen:dgram']
    except:
        p1_7a = "uninstalled"
    try:
        p1_7b = services['svc:/network/chargen:stream']
    except:
        p1_7b = "uninstalled"

    try:
        p1_8a = services['svc:/network/daytime:dgram']
    except:
        p1_8a = "uninstalled"
    try:
        p1_8b = services['svc:/network/daytime:stream']
    except:
        p1_8b = "uninstalled"

    report.append([get_name(), p0_1, p0_2a, p0_2b, p0_2c, p0_2d, p0_2e, p0_2f,
                  p0_2g, p0_2h, p0_2i, p0_2j, p0_2k, p1_1, p1_2, p1_3, p1_4a,
                  p1_4b, p1_4c, p1_4d, p1_5a, p1_5b, p1_6a, p1_6b, p1_7a,
                  p1_7b, p1_8a, p1_8b, p4_3, p4_4, p4_5a, p4_5b, p4_8a, p4_8b])


###
### making sure that /var/spool/cron/crontabs/root is always the path
### of the root crontab
###
@task
def solaris_crontab_path_ok():
    cp = "command"
    crontab_l = su("echo @%s@;crontab -l|cksum|cut -f1" % cp)
    cron_file = su("echo @%s@;cksum /var/spool/cron/crontabs/root|cut -f1" % cp)
    crontab_l = _get_command_output(crontab_l, cp)
    cron_file = _get_command_output(cron_file, cp)
    assert crontab_l == cron_file


###
### cfg2html (http://www.cfg2html.com) is one of my "platform tools"
### with this task I schedude the execution of cfg2html once a month
###
@task
def append_cfg2html_to_solaris_crontab():
    cronfile = "/var/spool/cron/crontabs/root"
    cfg2html_path = "/opt/pt_platform_tools/cfg2html/cfg2html_solaris"
    cfg2html_output = "/var/pt_platform_tools/output/cfg2html"
    cfg2html_log = "/var/pt_platform_tools/log/cfg2html.log"
    runme = """
#!/bin/sh -eu
cat >> %s  << EOF
# monthly cfg2html
05 00 2 * * %s -o %s >> %s 2>&1 < /dev/null
EOF
""" % (cronfile, cfg2html_path, cfg2html_output, cfg2html_log)
    run_string(runme, as_root='1')


###
### with this task I get the output from all cfg2html collectors
### this will only run on systems with command mkdir. ie. Linux
###
@task
def get_cfg2html():
    localdir = '/tmp/cfg2html/%s' % get_name()
    local('mkdir -p %s' % localdir)
    get('/var/pt_platform_tools/output/cfg2html/*', localdir)


@task
def zabbix_agentd():
    # su('pkill zabbix_agentd', warn_only=True)
    # run("svcs zabbix_agentd", warn_only=True)
    uname = run("uname")
    release = run("uname -r")
    if (uname == "SunOS"):
        if (release == "5.10"):
            configfile = "/usr/local/zabbix/conf/zabbix_agentd.conf"
        elif (release == "5.11"):
            configfile = "/usr/local/zabbix/etc/zabbix_agentd.conf"
        servicerestart = "svcadm restart zabbix_agentd"
    elif (uname == "Linux"):
        configfile = "/etc/zabbix/zabbix_agentd.conf"
        servicerestart = "service zabbix-agent restart"
    elif (uname == "HP-UX"):
        if (release == "B.11.11"):
            configfile = "/usr/local/zabbix/etc/zabbix_agentd.conf"
        elif (release == "B.11.31"):
            configfile = "/usr/local/zabbix/conf/zabbix_agentd.conf"
        servicerestart = "/sbin/init.d/zabbix-agentd restart"
    else:
        print("Unexpected OS")
        return
    runme = """
#!/bin/sh -eu
configfile=%s
paramname=platform.proc.mostcpu
if /usr/bin/test -e $configfile
then
  if grep $paramname $configfile
  then
    echo $paramname already in $configfile
    exit 1
  else
    echo >> $configfile
    echo '# $paramname autoadd by fabric' >> $configfile
    echo "UserParameter=$paramname,ps -fea    |\
    sort -nrk 4    |    awk '{print \$4;exit}'" >> $configfile
    echo >> $configfile
  fi
else
  echo no configfile
  exit 1
fi
""" % (configfile)

    if run_string(runme, as_root='1').succeeded:
        su(servicerestart, warn_only=True)


###
### Get some fields from a shadow like input
###
def _get_shadow_fields(shadow, user, fields, join_with=':'):
    for line in shadow.splitlines():
        line = line.split(':')
        if len(line) <= 0:
            continue
        if len(line[0]) <= 0:
            continue
        if line[0][0] == '#':
            continue
        if line[0] == user:
            r = []
            for f in fields:
                r.append(line[f])
            if join_with is not None:
                return join_with.join(r)
            else:
                return r


###
### Get the value of a configuration parameter from a "param(sep)val"
### format like file
###
def _get_config_param(config, param, default='', sep="\s+", comment="^\s*#",
                      flags=re.I):
    r = default
    for line in config.splitlines():
        if re.match(comment, line, flags):
            continue
        line = re.split(sep, line.strip(), 1, flags)
        if len(line) <= 1:
            continue
        if re.match("^%s$" % (param), line[0].strip(), flags):
            r = line[1].strip()
    return r


###
### Gets an array of the fields that match a criteria
###
def _get_fields(input_text, select_filter, field_number, field_pattern,
                sep="\s+", flags=re.I):
    r = []
    for line in input_text.splitlines():
        if not re.match(select_filter, line, flags):
            continue
        line = re.split(sep, line.strip(), flags=flags)
        if len(line) < field_number + 1:
            continue
        if re.match(field_pattern, line[field_number], flags):
            r.append(line[field_number])
    return r


###
### building some "security" report
###
@task
def security_checks_linux():

    # initializing
    # names
    n = {}
    # recommended value
    r = {}
    # actual value
    v = {}
    # complies
    c = {}

    checks = ["0.1a",
              "0.1b",
              "0.2a",
              "0.2b",
              "0.2c",
              "0.2d",
              "0.2e",
              "0.2f",
              "0.2g",
              "0.2h",
              "0.2i",
              "0.2j",
              "0.2k",
              "1.1",
              "1.2",
              "1.3",
             ]

    with settings(hide('stderr'), hide('stdout'), hide("running")):
        # doing security checks
        for check in checks:
            if check == "0.1a":
                # check name
                n[check] = ("Aplicar todos los Security Hotfixes del Sistema "
                            "Operativo -1-")
                # check recommended value
                r[check] = "Aplicado"
                # check calculation
                v[check] = "Ir a access.redhat.com"
                # compilance
                c[check] = "N/A"

            elif check == "0.1b":
                # check name
                n[check] = ("La Contraseña de root debe ser cambiada cada "
                            "cierto tiempo")
                # check recommended value
                r[check] = "1:60:7::"
                # check calculation
                v[check] = su("echo @cmnd@;cat /etc/shadow")
                v[check] = _get_command_output(v[check], "cmnd")
                v[check] = _get_shadow_fields(v[check], "root", [3, 4, 5, 6, 7])

            elif check == "0.2a":
                # check name
                n[check] = ("Establecer LogLevel VERBOSE Si no existe, añadir y"
                            "configurar")
                # check recommended value
                r[check] = "VERBOSE"
                # check calculation
                v[check] = su("echo @cmnd@;cat /etc/ssh/sshd_config")
                v[check] = _get_command_output(v[check], "cmnd")
                v[check] = _get_config_param(v[check], "LogLevel", "INFO")

            elif check == "0.2b":
                # check name
                n[check] = ("Establecer Protocol   2. Si no existe, añadir y "
                            "configurar")
                # check recommended value
                r[check] = "2"
                # check calculation
                v[check] = su("echo @cmnd@;cat /etc/ssh/sshd_config")
                v[check] = _get_command_output(v[check], "cmnd")
                v[check] = _get_config_param(v[check], "Protocol", "2,1")

            elif check == "0.2c":
                # check name
                n[check] = ("Establecer X11Forwarding no. Si no existe, añadir"
                            " y configurar")
                # check recommended value
                r[check] = "no"
                # check calculation
                v[check] = su("echo @cmnd@;cat /etc/ssh/sshd_config")
                v[check] = _get_command_output(v[check], "cmnd")
                v[check] = _get_config_param(v[check], "X11Forwarding", "no")

            elif check == "0.2d":
                # check name
                n[check] = ("Establecer IgnoreRhosts yes. Si no existe, añadir "
                            "y configurar")
                # check recommended value
                r[check] = "yes"
                # check calculation
                v[check] = su("echo @cmnd@;cat /etc/ssh/sshd_config")
                v[check] = _get_command_output(v[check], "cmnd")
                v[check] = _get_config_param(v[check], "IgnoreRhosts", "yes")

            elif check == "0.2e":
                # check name
                n[check] = ("Establecer RhostsAuthentication no. Si no existe, "
                            "añadir y configurar - descontinuado -")
                # check recommended value
                r[check] = "SSH-2.0-OpenSSH_3.7"
                # check calculation
                v[check] = (connections[env.host_string].
                            get_transport().
                            remote_version)
                # compilance
                c[check] = "Si" if (v[check] >= r[check]) else "No"

            elif check == "0.2f":
                # check name
                n[check] = ("Establecer RhostsRSAAuthentication no. Si no "
                            "existe, añadir y configurar")
                # check recommended value
                r[check] = "no"
                # check calculation
                v[check] = su("echo @cmnd@;cat /etc/ssh/sshd_config")
                v[check] = _get_command_output(v[check], "cmnd")
                v[check] = _get_config_param(v[check],
                                             "RhostsRSAAuthentication",
                                             "no")

            elif check == "0.2g":
                # check name
                n[check] = ("Establecer PermitRootLogin no. Si no existe, "
                            "añadir y configurar")
                # check recommended value
                r[check] = "no"
                # check calculation
                v[check] = su("echo @cmnd@;cat /etc/ssh/sshd_config")
                v[check] = _get_command_output(v[check], "cmnd")
                v[check] = _get_config_param(v[check], "PermitRootLogin", "yes")

            elif check == "0.2h":
                # check name
                n[check] = ("Establecer PermitEmptyPasswords no. Si no existe, "
                            "añadir y configurar")
                # check recommended value
                r[check] = "no"
                # check calculation
                v[check] = su("echo @cmnd@;cat /etc/ssh/sshd_config")
                v[check] = _get_command_output(v[check], "cmnd")
                v[check] = _get_config_param(v[check],
                                             "PermitEmptyPasswords",
                                             "no")

            elif check == "0.2i":
                # check name
                n[check] = ("Establecer Banner")
                # check recommended value
                r[check] = "/etc/issue"
                # check calculation
                v[check] = su("echo @cmnd@;cat /etc/ssh/sshd_config")
                v[check] = _get_command_output(v[check], "cmnd")
                v[check] = _get_config_param(v[check],
                                             "Banner",
                                             "none")

            elif check == "0.2j":
                # check name
                n[check] = ("Establecer root propietario de sshd_config y "
                            "ssh_config")
                # check recommended value
                r[check] = "0:[0-9]+ 0:[0-9]+"
                # check calculation
                v[check] = run("stat --printf '%u:%g ' /etc/ssh/sshd_config "
                               "/etc/ssh/ssh_config")

            elif check == "0.2k":
                # check name
                n[check] = ("Restringir el acceso de escritura a sshd_config y"
                            "ssh_config para el propietario del archivo")
                # check recommended value
                r[check] = ".......0. .......0."
                # check calculation
                v[check] = run("stat --printf '0%a ' /etc/ssh/sshd_config "
                               "/etc/ssh/ssh_config")
                v[check] = ' '.join([bin(int(x, 8)).replace('0b', '').zfill(9)
                                     for x in v[check].split()])
                assert (len(v[check]) == 19)

            elif check == "1.1":
                # check name
                n[check] = ("Inhabilitar el servicio xinetd/telnet")
                # check recommended value
                r[check] = "0"
                # check calculation
                v[check] = run("netstat -ntl")
                v[check] = str(len(_get_fields(v[check],
                                               "^tcp.*",
                                               3,
                                               ".*:22$")))

            elif check == "1.2":
                # check name
                n[check] = ("Inhabilitar el servicio xinetd/finger")
                # check recommended value
                r[check] = "0"
                # check calculation
                v[check] = run("netstat -ntl")
                open_sockets = 0
                for line in v[check].splitlines():
                    line = line.split()
                    if re.match("^tcp.*", line[0]):
                        if re.match(".*:79$", line[3]):
                            open_sockets += 1
                v[check] = str(open_sockets)

            elif check == "1.3":
                # check name
                n[check] = ("Inhabilitar el servicio xinetd/tftp e xinetd/ftp")
                # check recommended value
                r[check] = "0 0"
                # check calculation
                v[check] = run("netstat -nul")
                open_tftp_sockets = 0
                for line in v[check].splitlines():
                    line = line.split()
                    if re.match("^udp.*", line[0]):
                        if re.match(".*:69$", line[3]):
                            open_tftp_sockets += 1
                v[check] = str(open_tftp_sockets)

    # check evaluation
    for check in checks:
        if check not in c:
            if re.match("^\s*%s\s*$" % r[check], v[check], re.I):
                c[check] = "Si"
            else:
                c[check] = "No"

    # building header
    if not hasattr(report, 'header'):
        report.header = ["hostname"]
        for check in checks:
            report.header.append("%s - %s (%s)" % (check,
                                                   n[check],
                                                   r[check]))
            report.header.append("%s cumple" % check)

    # building report columns
    row = []
    row.append(get_name())
    for check in checks:
        row.append(v[check])
        row.append(c[check])
    report.append(row)
