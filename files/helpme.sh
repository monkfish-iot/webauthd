#!/bin/sh
# 
# File:   helpme.sh
# Author: liugang
#
# Created on 2021年9月7日, 下午1:53:15
#


while [[ 1 ]]
do

        run=`ps -www |grep webauthd | grep -v grep |  grep -v nginx`
 
        if [ "$run" ==  ""  ]; then
        	 
                /sbin/webauthd
              
             #   date >> /tmp/log.txt
        fi
 
        sleep 3
done