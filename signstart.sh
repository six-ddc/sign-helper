#!/usr/bin/env bash
exec 1>> /root/git/sign-helper/sign.log  2>&1
sleeptime=` shuf -i 0-10 -n 1`  ;
echo  "sleep  ${sleeptime}"
sleep  ${sleeptime}
/root/git/sign-helper/sign.sh  all  
