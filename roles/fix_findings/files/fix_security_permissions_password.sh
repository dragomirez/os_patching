#!/bin/bash

### fix permissions
[[ `stat -L -c %A /etc/passwd | grep "^-..-.--.--"| wc -l` -eq 0 ]] &&  /bin/chmod 0644 /etc/passwd
[[ `stat -L -c %A /etc/shadow | grep "^-.--------"| wc -l` -eq 0 ]] &&  /bin/chmod 0400 /etc/shadow
[[ `stat -L -c %A /etc/gshadow | grep "^-.--------"| wc -l` -eq 0 ]] && /bin/chmod 0400 /etc/gshadow
[[ `stat -L -c %A /etc/group | grep "^-..-.--.--"| wc -l` -eq 0 ]] &&  /bin/chmod 0644 /etc/group
/bin/chown root /etc/login.defs
[[ `stat -L -c %A /etc/login.defs | grep "^-..-.--.--"| wc -l` -eq 0 ]] && /bin/chmod 0644 /etc/login.defs
/bin/chown root:root /etc/exports
[[ `stat -L -c %A /etc/exports | grep "^-..-.-----"| wc -l` -eq 0 ]] &&  /bin/chmod 0640 /etc/exports
/bin/chown root /var/log/messages
[[ `stat -L -c %A /var/log/messages | grep "^-..-------"| wc -l` -eq 0 ]] && /bin/chmod 0600 /var/log/messages
/bin/chown root /var/log/secure
[[ `stat -L -c %A /var/log/secure | grep "^-..-------"| wc -l` -eq 0 ]] && /bin/chmod 600 /var/log/secure
/bin/chown root:utmp /var/log/wtmp
[[ `stat -L -c %A /var/log/wtmp | grep "^-..-.--.--"| wc -l` -eq 0 ]] && /bin/chmod 644 /var/log/wtmp
/bin/chown root /etc/pam.d/login
[[ `stat -L -c %A /etc/pam.d/login | grep "^-..-.--.--"| wc -l` -eq 0 ]] && /bin/chmod 0644 /etc/pam.d/login
chown root /etc/pam.d/system-auth
[[ `stat -L -c %A /etc/pam.d/system-auth  | grep "^-..-.--.--"| wc -l` -eq 0 ]] &&  /bin/chmod 0644 /etc/pam.d/system-auth ;
/bin/chown root /etc/security/opasswd
[[ `stat -L -c %A /etc/security/opasswd  | grep "^-..-.--.--"| wc -l` -eq 0 ]] &&  /bin/chmod 0644 /etc/security/opasswd 
/bin/chown root:utmp /var/run/utmp
[[ `stat -L -c %A /var/run/utmp | grep "^-..-.--.--"| wc -l` -eq 0 ]] && /bin/chmod 644 /var/run/utmp
/bin/chown root:root /etc/filesystems
[[ `stat -L -c %A /etc/filesystems | grep "^-.--.--.--"| wc -l` -eq 0 ]] && /bin/chmod 444 /etc/filesystems
/bin/chown root:root /etc/fstab
[[ `stat -L -c %A /etc/fstab | grep "^-.--.--.--"| wc -l` -eq 0 ]] && /bin/chmod 444 /etc/fstab

## fix empty password issue
[[ `grep -E "^[a-zA-Z][a-zA-Z0-9]*::" /etc/shadow|wc -l` -gt 0 ]] && sed  -i".orig_`date +%Y%m%d`" 's/^\([a-zA-Z][a-zA-Z0-9]*\)::/\1:!!:/g' /etc/shadow
##

#Password auth/manipulation hardening
#backup the pwquality.conf  file
/bin/cp -p /etc/security/pwquality.conf /etc/security/pwquality.conf.orig_`date +%Y%m%d`

#Set to 3 the number of characters in the new password that must not be present in the old password.
if [ `grep -E "^[ \t]*difok[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "difok = 3"    >> /etc/security/pwquality.conf
  else
    CHECK=`grep -E "^[ \t]*difok[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -lt 3 ]] && sed -i "s/^[ \t]*difok[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$/difok = 3/" /etc/security/pwquality.conf 
fi

#Set to 8 Minimum acceptable size for the new password
if [ `grep -E "^[ \t]*minlen[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "minlen = 8"    >> /etc/security/pwquality.conf
  else
    CHECK=`grep -E "^[ \t]*minlen[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -lt 8 ]] && sed -i "s/^[ \t]*minlen[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$/minlen = 8/" /etc/security/pwquality.conf 
fi

#Set to 2  maximum number of allowed consecutive same characters in the new password
if [ `grep -E "^[ \t]*maxrepeat[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "maxrepeat = 2"    >> /etc/security/pwquality.conf
  else
    CHECK=`grep -E "^[ \t]*maxrepeat[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -ne 2 ]] && sed -i "s/^[ \t]*maxrepeat[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$/maxrepeat = 2/" /etc/security/pwquality.conf 
fi

#Set to -1 The maximum credit for having digits in the new password. 
if [ `grep -E "^[ \t]*dcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "dcredit = -1"    >> /etc/security/pwquality.conf
  else
    CHECK=`grep -E "^[ \t]*dcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -gt -1  ]] && sed -i "s/^[ \t]*dcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$/dcredit = -1/" /etc/security/pwquality.conf 
fi

#Set to -1 The maximum credit for having uppercase characters in the new password. 
if [ `grep -E "^[ \t]*ucredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "ucredit = -1"    >> /etc/security/pwquality.conf
  else
    CHECK=`grep -E "^[ \t]*ucredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -gt -1  ]] && sed -i "s/^[ \t]*ucredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$/ucredit = -1/" /etc/security/pwquality.conf 
fi


#Set to -1 The maximum credit for having lowercase characters in the new password. 
if [ `grep -E "^[ \t]*lcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "lcredit = -1"    >> /etc/security/pwquality.conf
  else
    CHECK=`grep -E "^[ \t]*lcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -gt -1  ]] && sed -i "s/^[ \t]*lcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$/lcredit = -1/" /etc/security/pwquality.conf 
fi



#Set to -1 The maximum credit for having other characters in the new password. 
if [ `grep -E "^[ \t]*ocredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "ocredit = -1"    >> /etc/security/pwquality.conf
  else
    CHECK=`grep -E "^[ \t]*ocredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -gt -1  ]] && sed -i "s/^[ \t]*ocredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$/ocredit = -1/" /etc/security/pwquality.conf 
fi


# Is HISTORY been set to 6 or more passwords?

#backup the pwquality.conf  file
/bin/cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth-ac.orig_`date +%Y%m%d`


if [ `grep -E "^[ \t]*password[ \t]*sufficient[ \t]*pam_unix.so.*remember=" /etc/pam.d/system-auth| wc -l` -eq 0 ]
  then
    sed -i "s/^\([ \t]*password[ \t]*sufficient[ \t]*pam_unix.so.*\)/\1 remember=6/" /etc/pam.d/system-auth
  else
    CHECK=`grep -E "^[ \t]*password[ \t]*sufficient[ \t]*pam_unix.so.*remember=" /etc/pam.d/system-auth|tr " " "\n"|grep  "remember=" | awk -F "=" '{print $2}'`
    [[ $CHECK -lt 6  ]] && sed -i "s/^\([ \t]*password[ \t]*sufficient[ \t]*pam_unix.so.*\)remember=$CHECK\(.*$\)/\1 remember=6 \2/" /etc/pam.d/system-auth 
fi

