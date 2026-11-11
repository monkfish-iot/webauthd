#!/bin/sh
. /lib/functions.sh

get_https_conf() {
	local https_ip
	local https_port
	local flag
	config_get flag $1 flag
	if [ $flag == 0 ]; then  	
		config_get https_ip $1 https_ip
		config_get https_port   $1 https_port
		# 判断https服务器是否是本地服务器
		mkdir -p /var/etc
		sed -e "s#|HTTPS_PORT|#$https_port#g" \
	    	/usr/local/natshell/nac2/https/nac_https_server_nginx.conf.template > /var/etc/nac_https_server_nginx.conf
	
	       [ -L /usr/local/natshell/nac2/https/nac_https_server_nginx.conf ] || ln -nsf /var/etc/nac_https_server_nginx.conf /usr/local/natshell/nac2/https/nac_https_server_nginx.conf
	
		# 开启nginx服务器
		/usr/sbin/nginx -c /usr/local/natshell/nac2/https/nac_https_server_nginx.conf
		echo $? 
	fi
}

[ ! -x "/usr/logs" ] && mkdir /usr/logs

# 关闭nginx服务器
nginx_pid=`cat /usr/logs/nac_https_nginx.pid`
[ $? -eq 0 ] && [ -n $nginx_pid ] && kill -9 $nginx_pid &&  kill -9 $(($nginx_pid+1));
	
config_load nac2
config_foreach  get_https_conf  portal
