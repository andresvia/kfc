# -*- coding: utf-8 -*-
# seq

### assorted,
### un-organized,
### un-portable &
### un-documented
### one-shot ugly functions and hacks
### to do fast work and requirements
### that have no place in fabfile.py


execfile('fabfile.py')


from fabric.api import put


@task
def _get_hba_info():
    su("/usr/sbin/fcinfo hba-port", warn_only=True)


@task
def _get_pass_param():
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


def _get_existing_users(user_list):
    existing_users = []
    for user in user_list:
        with settings(hide('stderr', 'stdout', 'running', 'warnings'),
                      warn_only=True):
            idux = run("id %s" % user)
            if idux.succeeded:
                existing_users.append(user)
    return existing_users


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


@task
def _get_format():
    su("format < /dev/null ; true")


@task
def _get_multipathll():
    su("multipath -ll ; true")


@task
def set_rackt_value(param_name):
    os_family = _get_os_family()
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


def _get_os_family():
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


@task
def find_core():
    run("date")
    su("time find / \! "
       "-local "
       "-prune -o "
       "\( -name core -a -type f \) "
       "-exec ls -lh '{}' \; | tee")
    run("date")


@task
def find_funky_tasks():
    su("crontab -l | grep -i sh", warn_only=True)


@task
def find_hbas_solaris():
    name = get_name()
    result = su("/usr/sbin/fcinfo hba-port", warn_only=True)
    if result.succeeded:
        f = open("/tmp/hbas/%s.log" % name, "w")
        f.write(result)
        f.close()


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


@task
@runs_once
def print_report(header='1', sort='0', separator='\t', vseparator='\n'):
    print(gen_report(header, sort, separator, vseparator))
    serverinfo.server_info_cache.save()


def gen_report(header, sort, separator, vseparator):
    if (sort == '1'):
        report.sort()
    if header == '1':
        report.insert(0, report.header)
    return(vseparator.join([separator.join(x) for x in report]))


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
    result = result.replace('\n', '\\n').replace('\t', '\\t')
    report.append([get_name(), result])


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


@task
def solaris_mpver():
    report.header = ['hostname', 'mpver', 'mppaths']
    command_prefix = "command"

    localscript = """

echo -n 'version mapthadm: ' ; mpathadm -V |grep -i version
echo -n "number of paths: " ; mpathadm list lu | grep 'Operational Path Count:' | sort -ur | head -1

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


@task
def solaris_volver():
    report.header = ['hostname', 'ver SUNWvolr svm', 'ver SUNWzfskr zfs', 'ver SUNWmpapir mpio']
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


@task
def linux_volver():
    report.header = ['hostname', 'device-mapper-multipath', 'lvm2', 'e2fsprogs-libs']
    command_prefix = "command"

    localscript = """

rpm -q -a | egrep '^device-mapper-multipath-' | head -n1 | awk 'BEGIN{printf("")}{print}'
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

