#!/bin/bash

### check permissions
[[ `stat -L -c %A /etc/passwd | grep "^-..-.--.--"| wc -l` -ne 0 ]] || echo "Need to fix permissions of /etc/passwd"
[[ `stat -L -c %A /etc/shadow | grep "^-.--------"| wc -l` -ne 0 ]] ||  echo "Need to fix permissions of /etc/shadow"
[[ `stat -L -c %A /etc/gshadow | grep "^-.--------"| wc -l` -ne 0 ]] || echo "Need to fix permissions of  /etc/gshadow"
[[ `stat -L -c %A /etc/group | grep "^-..-.--.--"| wc -l` -ne 0 ]] ||  echo "Need to fix permissions of  /etc/group"
[[ `stat -L -c %A /etc/login.defs | grep "^-..-.--.--"| wc -l` -ne 0 ]] || echo "Need to fix permissions of /etc/login.defs"
[[ `stat -L -c %A /etc/exports | grep "^-..-.-----"| wc -l` -ne 0 ]] ||  echo "Need to fix permissions of /etc/exports"
[[ `stat -L -c %A /var/log/messages | grep "^-..-------"| wc -l` -ne 0 ]] || echo "Need to fix permissions of /var/log/messages"
[[ `stat -L -c %A /var/log/secure | grep "^-..-------"| wc -l` -ne 0 ]] || echo "Need to fix permissions of /var/log/secure"
[[ `stat -L -c %A /var/log/wtmp | grep "^-..-.--.--"| wc -l` -ne 0 ]] || echo "Need to fix permissions of /var/log/wtmp"
[[ `stat -L -c %A /etc/pam.d/login | grep "^-..-.--.--"| wc -l` -ne 0 ]] || echo "Need to fix permissions of /etc/pam.d/login"
[[ `stat -L -c %A /etc/pam.d/system-auth  | grep "^-..-.--.--"| wc -l` -ne 0 ]] ||  echo "Need to fix permissions of /etc/pam.d/system-auth"
[[ `stat -L -c %A /etc/security/opasswd  | grep "^-..-.--.--"| wc -l` -ne 0 ]] ||  echo "Need to fix permissions of /etc/security/opasswd"
[[ `stat -L -c %A /var/run/utmp | grep "^-..-.--.--"| wc -l` -ne 0 ]] || echo "Need to fix permissions of /var/run/utmp"
[[ `stat -L -c %A /etc/filesystems | grep "^-.--.--.--"| wc -l` -ne 0 ]] || echo "Need to fix permissions of /etc/filesystems"
[[ `stat -L -c %A /etc/fstab | grep "^-.--.--.--"| wc -l` -ne 0 ]] || echo "Need to fix permissions of /etc/fstab"

## fix empty password issue
[[ `grep -E "^[a-zA-Z][a-zA-Z0-9]*::" /etc/shadow|wc -l` -eq 0 ]] || echo "Empty password detected!"
##


#Password auth/manipulation hardening check

#Set to 3 the number of characters in the new password that must not be present in the old password.
if [ `grep -E "^[ \t]*difok[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "difok to be fixed" 
  else
    CHECK=`grep -E "^[ \t]*difok[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -ge 3 ]] ||  echo "difok to be fixed" 
fi

#Set to 8 Minimum acceptable size for the new password
if [ `grep -E "^[ \t]*minlen[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "minlen to be fixed"   
  else
    CHECK=`grep -E "^[ \t]*minlen[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -ge 8 ]] || echo "minlen to be fixed" 
fi

#Set to 2  maximum number of allowed consecutive same characters in the new password
if [ `grep -E "^[ \t]*maxrepeat[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "maxrepeat to be fixed"   
  else
    CHECK=`grep -E "^[ \t]*maxrepeat[ \t]*=[ \t]*[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -eq 2 ]] ||  echo "maxrepeat to be fixed"    
fi

#Set to -1 The maximum credit for having digits in the new password. 
if [ `grep -E "^[ \t]*dcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "dcredit to be fixed"   
  else
    CHECK=`grep -E "^[ \t]*dcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -le -1  ]] || echo "dcredit to be fixed" 
fi

#Set to -1 The maximum credit for having uppercase characters in the new password. 
if [ `grep -E "^[ \t]*ucredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "ucredit to be fixed"   
  else
    CHECK=`grep -E "^[ \t]*ucredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -le -1  ]] || echo "ucredit to be fixed" 
fi


#Set to -1 The maximum credit for having lowercase characters in the new password. 
if [ `grep -E "^[ \t]*lcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "lcredit to be fixed"   
  else
    CHECK=`grep -E "^[ \t]*lcredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -le -1  ]] || echo "lcredit to be fixed"  
fi


#Set to -1 The maximum credit for having other characters in the new password. 
if [ `grep -E "^[ \t]*ocredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| wc -l` -eq 0 ]
  then
    echo "ocredit to be fixed"      
  else
    CHECK=`grep -E "^[ \t]*ocredit[ \t]*=[ \t]*-?[1-9][0-9]*[ \t]*$" /etc/security/pwquality.conf| awk -F "=" '{print $2}'`
    [[ $CHECK -le -1  ]] || echo "ocredit to be fixed" 
fi


# Is HISTORY been set to 6 or more passwords?

if [ `grep -E "^[ \t]*password[ \t]*sufficient[ \t]*pam_unix.so.*remember=" /etc/pam.d/system-auth| wc -l` -eq 0 ]
  then
    echo "remember history in system-auth to be fixed"
  else
    CHECK=`grep -E "^[ \t]*password[ \t]*sufficient[ \t]*pam_unix.so.*remember=" /etc/pam.d/system-auth|tr " " "\n"|grep  "remember=" | awk -F "=" '{print $2}'`
    [[ $CHECK -ge 6  ]] || echo "remember history in system-auth to be fixed"
fi

