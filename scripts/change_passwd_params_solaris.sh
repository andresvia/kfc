#!/bin/bash

# av 2013

set -eu

operator=av
passwd_file=/etc/default/passwd
login_file=/etc/default/login
policy_file=/etc/security/policy.conf
new_file="$(mktemp)"

clean_up() {
  set +eu
  rm "$new_file"
  set -eu
}

backup_file()
{
  cp "$1" "$1.bak-$(date +%Y-%m-%d-%H-%M-%S-$operator)"
}
 
trap clean_up EXIT INT TERM

###
### Reemplazando passwd
### 
 
perl -lp \
-e 's|^\s*#*\s*MAXWEEKS\s*=\s*[0-9]*\s*$|MAXWEEKS=9|;' \
-e 's|^\s*#*\s*MINWEEKS\s*=\s*[0-9]*\s*$|MINWEEKS=1|;' \
-e 's|^\s*#*\s*PASSLENGTH\s*=\s*[0-9]*\s*$|PASSLENGTH=10|;' \
-e 's|^\s*#*\s*HISTORY\s*=\s*[0-9]*$|HISTORY=24|;' \
"$passwd_file" > "$new_file"

echo diff
diff "$passwd_file" "$new_file" | tee

read -p "replace? " replace_file

if [ "$replace_file" == y ]
then
  backup_file "$passwd_file"
  cp "$new_file" "$passwd_file"
fi

###
### Reemplazando login
### 

perl -lp \
-e 's|^\s*#*\s*RETRIES\s*=\s*[0-9]*\s*$|RETRIES=6|;' \
"$login_file" > "$new_file"

echo diff
diff "$login_file" "$new_file" | tee

read -p "replace? " replace_file

if [ "$replace_file" == y ]
then
  backup_file "$login_file"
  cp "$new_file" "$login_file"
fi

###
### Reemplazando policy
###

perl -lp \
-e 's/^\s*#*\s*LOCK_AFTER_RETRIES\s*=\s*(YES|NO)*\s*$/LOCK_AFTER_RETRIES=YES/;' \
"$policy_file" > "$new_file"

echo diff
diff "$policy_file" "$new_file" | tee

read -p "replace? " replace_file

if [ "$replace_file" == y ]
then
  backup_file "$policy_file"
  cp "$new_file" "$policy_file"
fi

trap - EXIT INT TERM
clean_up
exit 0

