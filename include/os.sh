#!/bin/bash
# shellcheck disable=SC2104,SC2155,SC2162,SC2181

:<<!
* @description: Get operating system's type
* @return: String 'centos'|'rhel'|'unknown'|...
!
get_os()
{
    local DISTRO='unknown'
    #local PM='unknown'
    if grep -qi "CentOS Linux" /etc/os-release; then
        DISTRO='centos'
        #PM='yum'
    elif grep -qi "Red Hat Enterprise Linux" /etc/os-release; then
        DISTRO='rhel'
    elif grep -qi "Amazon Linux" /etc/os-release; then
        DISTRO='amzn'
        #PM='yum'
    elif grep -qi "Oracle Linux Server" /etc/os-release; then
        DISTRO='ol'
    elif grep -qi "AlmaLinux" /etc/os-release; then
        DISTRO='almalinux'
    elif grep -qi "Rocky Linux" /etc/os-release; then
        DISTRO='rockylinux'
    # elif grep -Eqi "Aliyun" /etc/issue || grep -Eq "Aliyun" /etc/*-release; then
    #     DISTRO='aliyun'
    #     PM='yum'
    # elif grep -Eqi "Fedora" /etc/issue || grep -Eq "Fedora" /etc/*-release; then
    #     DISTRO='fedora'
    #     PM='yum'
    # elif grep -Eqi "Debian" /etc/issue || grep -Eq "Debian" /etc/*-release; then
    #     DISTRO='debian'
    #     PM='apt'
    # elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
    #     DISTRO='ubuntu'
    #     PM='apt'
    # elif grep -Eqi "Raspbian" /etc/issue || grep -Eq "Raspbian" /etc/*-release; then
    #     DISTRO='raspbian'
    #     PM='apt'
    else
        DISTRO='unknown'
    fi
    echo $DISTRO
}

:<<!
* @description: Get operating system's os version
* @return: String '7.5'|'7.6'|'7.7'|'7.8'|'7.9'|'unknown'|...
!
get_os_version()
{
    if grep -q " 7.5" /etc/redhat-release; then 
        echo "7.5"
    elif grep -q " 7.6" /etc/redhat-release; then 
        echo "7.6"
	elif grep -q " 7.7" /etc/redhat-release; then 
        echo "7.7"
	elif grep -q " 7.8" /etc/redhat-release; then 
        echo "7.8"
	elif grep -q " 7.9" /etc/redhat-release; then 
        echo "7.9"
    elif grep -q " 8.0" /etc/redhat-release; then 
        echo "8.0"
    elif grep -q " 8.1" /etc/redhat-release; then 
        echo "8.1"
    elif grep -q " 8.2" /etc/redhat-release; then 
        echo "8.2"
    elif grep -q " 8.3" /etc/redhat-release; then 
        echo "8.3"
    elif grep -q " 8.4" /etc/redhat-release; then 
        echo "8.4"
	elif grep -q " 8.5" /etc/redhat-release; then 
        echo "8.5"
	elif grep -q " 8.6" /etc/redhat-release; then 
        echo "8.6"
    elif grep -q " 8.7" /etc/redhat-release; then 
        echo "8.7"
    else
        echo "unknown"
    fi
}

:<<!
* @description: Check if current OS is a CentOS or RedHat Linux
* @return: 0|1
!
is_rhel_or_centos()
{
    local dist;
    dist=$(get_os)
    if [ "${dist}" = "centos" ] ||  [ "${dist}" = "rhel" ] ||  [ "${dist}" = "ol" ]; then return 0; else return 1; fi
}

is_amzn()
{
    local dist;
    dist=$(get_os)
    if [ "${dist}" = 'amzn' ]; then return 0;else return 1; fi
}

is_alma()
{
    local dist;
    dist=$(get_os)
    if [ "${dist}" = 'almalinux' ]; then return 0;else return 1; fi
}

is_rocky()
{
    local dist;
    dist=$(get_os)
    if [ "${dist}" = 'rockylinux' ]; then return 0;else return 1; fi
}

:<<!
* @description: Check if the current OS is a 64bit system
* @return: 0|1
!
is_x86_64()
{    
    if ( uname -a | grep -q x86_64 ); then return 0; else return 1; fi
}

:<<!
* @description: Check if the current OS is a CentOS 7.x os RedHat 7.x
* @return: 0|1
!
is_rhel7x()
{   
	if [ "${IGNORE_RHEL_VERSION_CHECKING}" == 1 ]; then
		return 0
	else     
		if grep -q " 7.5" /etc/redhat-release || grep -q " 7.6" /etc/redhat-release || grep -q " 7.7" /etc/redhat-release || grep -q " 7.8" /etc/redhat-release || grep -q " 7.9" /etc/redhat-release; then return 0; else return 1; fi
	fi
}

is_rhel8x()
{   
	if [ "${IGNORE_RHEL_VERSION_CHECKING}" == 1 ]; then
		return 0
	else     
		if grep -q " 8.0" /etc/redhat-release || grep -q " 8.1" /etc/redhat-release || grep -q " 8.2" /etc/redhat-release || grep -q " 8.3" /etc/redhat-release || grep -q " 8.4" /etc/redhat-release || grep -q " 8.5" /etc/redhat-release || grep -q " 8.6" /etc/redhat-release || grep -q " 8.7" /etc/redhat-release; then return 0; else return 1; fi
	fi
}

is_amzn2()
{   
	if [ "${IGNORE_AMZN_VERSION_CHECKING}" == 1 ]; then
		return 0
	else     
		if grep -q "release 2" /etc/system-release; then return 0; else return 1; fi
	fi
}

:<<!
* @description: Check if the current script is executed under a sudo user
* @return: 0|1
!
is_root()
{
    if ( id | grep -q "uid=0(root)" ); then return 0; else return 1;fi
}

:<<!
* @description: Check if the OS's system clock is earlier than package's date
* @return: 0|1
!
is_valid_ntpdate()
{
    local datetest=$(dirname "${BASH_SOURCE[0]}")"/os.sh"
    local date1=$(stat -c %y "${datetest}" | awk '{print $1}'|sed s/-//g)
    local date2=$(date +%Y%m%d)
	
	if [ ! "${date2}" -lt "${date1}" ]; then return 0; else return 1; fi
}

:<<!
* @description: Check if the given number is a valid port
* @return: 0|1
!
is_valid_port() {
    local port=$1
    local reg_int='^[1-9][0-9]*$|^[-][1-9][0-9]*$|^0$'
    if [[ ${port} =~ ${reg_int} ]] && [[ ${port} -gt 0 ]] && [[ ${port} -le 65535 ]] ; then return 0;else return 1; fi
}

:<<!
* @description: Check if the given number is a valid RFC1700 port
* @return: 0|1
!
is_valid_RFC1700_port() {
    local port=$1
    local reg_int='^[1-9][0-9]*$|^[-][1-9][0-9]*$|^0$'
    if [[ ${port} =~ ${reg_int} ]] && [[ ${port} -ge 1025 ]] && [[ ${port} -le 32767 ]] ; then return 0;else return 1; fi
}

:<<!
* @description: Check if the given string is a valid IPv4 address
* @return: 0|1|2
!
is_valid_ipv4() {
    local IP=$1
    local VALID_CHECK=$(echo "${IP}" | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print "yes"}')
    if echo "${IP}" | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$">/dev/null; then
        if [ "${VALID_CHECK:-no}" == "yes" ]; then
            return 0
        else
            return 1
        fi
    else
        return 2
    fi
}

:<<!
* @description: Check if the given port is in use
* @return: 0|1
!
is_port_using() {
    local port=$1
    # is_valid_port ${port}
    # if [ $? -eq 0 ];then
    #    < /dev/tcp/localhost/${port} &>/dev/null && return 0 || return 1
    # fi
    # return 1
	local checkport=$(ss -ltn | grep ":${port} ")
	if [ -z "$checkport" ]; then return 0; else return 1; fi
}

:<<!
* @description: Check if the given path is immutable:i and a
* @return: 0|1
!
is_lsattr() {
    local checkpath=$1
	
	if [ -d "${checkpath}" ]; then
		#if [ -z "$(lsattr -d "${checkpath}" | cut -d" " -f1 | grep -e "i" -e "a")" ]; then return 0; else return 1; fi
        #local check_value=$(lsattr -d "${checkpath}" | cut -d" " -f1 | grep -q -e "i" -e "a" >/dev/null 2>&1)
        #if [ $? -ne 0 ] || [ -n "$check_value" ]; then return 0; else return 1; fi
		if [ ! $(lsattr -d "$checkpath" | cut -d" " -f1 | grep -e "i" -e "a") ]; then return 0; else return 1; fi
	fi
	return 0
}

:<<!
* @description: Check if the given path is immutable: i
* @return: 0|1
!
is_immutable() {
    local checkpath=$1	
    if [ -e "${checkpath}" ]; then
	if [ $(lsattr -d "$checkpath" | cut -d" " -f1 | grep -e "i") ]; then return 0; else return 1; fi
    fi
    return 0
}

:<<!
* @description: Get the hostname of current OS
* @return: string
!
get_hostname() {
    hostname
}

:<<!
* @description: Get the total CPU core count of current OS
* @return: integer
!
get_cpu_count() {
    nproc
    # https://stackoverflow.com/questions/6481005/how-to-obtain-the-number-of-cpus-cores-in-linux-from-the-command-line
}

:<<!
* @description: Get total memory size of current OS in MB unit
* @return: integer Unit:MB
!
get_memory() {
    free -m | awk '/^Mem:/{print $2}'
    # https://www.binarytides.com/linux-command-check-memory-usage/
}

:<<!
* @description: Get available disk size of the given path
* @return: integer Unit:MB
!
get_disk_available_size()
{
    local topdir=$1
    while [ ! -d "${topdir}" ]; do
        topdir=$(dirname "${topdir}")
    done

    local disk_size_MB=$(df -h -m "${topdir}" | awk '{if (NR>1){print $4}}')
    echo "${disk_size_MB}"
}

:<<!
* @description: Get available disk percent of the given path
* @return: integer Unit:MB
!
get_disk_usage_percent()
{
    local topdir=$1
    while [ ! -d "${topdir}" ]; do
        topdir=$(dirname "${topdir}")
    done

    local disk_usage=$(df -h -m "${topdir}" | awk '{if (NR>1){print $5}}')
    echo "${disk_usage}"
}

:<<!
* @description: Get the first level folder name of the given path
* @return: string
!
get_rootdir() {
	local rootdir="/"$(echo "$1" | cut -d"/" -f2)
	echo "${rootdir}"
}

:<<!
* @description: Check the parent folder name of the given path
* @return: string
!
get_parentdir()
{
    dirname "$1"
}

:<<!
* @description: Check status of the given path
* @return: 0(does not exist)|1(folder)|2(file)
!
get_path_status() {
    local PATH=$1
    local status=0  # does not exist
    if [ -e "${PATH}" ];then
        status=2  # file or other object
        if [ -d "${PATH}" ];then
            status=1  # folder
        fi
    fi
    echo "${status}"
}

:<<!
* @description: mkdir for file path
* @return: 0
!
mkdir_of_file() {
    local path=$(dirname $1)
	mkdir -p "${path}"
}
