#!/bin/bash
# shellcheck disable=SC2104,SC2155,SC2162,SC2181

:<<!
* @description: Check if the given rpm packages have been installed
* @param: package The package name needs to be checked
* @return: 0|1
!
rpm_installed()
{    
    local package=$1  
    if ( rpm -qa "$package" | grep -q "$package"  > /dev/null); then return 0; else return 1; fi
}


:<<!
* @description: get rpm version
* @param: package The package name needs to be checked
* @return: version or empty
!
rpm_installed_version()
{    
    local package=$1
	local ver=$(rpm -q --queryformat '%{VERSION}' "$package")
    local ret=$?
	if (echo "$ver" | grep -q 'not installed'); then
		echo "";
	else
		if [ $ret -eq 0 ]; then 
			echo $ver; 
		else 
			echo ""; 
		fi
	fi
}

:<<!
* @description: Check if the given command already exists
* @param: command_value The command name needs to be checked
* @return: 0|1
!
command_exists()
{
    local command_value=$1  
    if command -v "$command_value" > /dev/null;then return 0; else return 1; fi;
}

:<<!
* @description: Check if the given systemd service already exists
* @param: service_name The systemd service name needs to be checked
* @return: 0|1
!
systemd_service_exists()
{
    local service_name=$1
    echo "${service_name}" | grep -qE '\.service$'  >& /dev/null
    if [[ $? -ne 0 ]];then
        local file="/usr/lib/systemd/system/${service_name}.service"
    else
        local file="/usr/lib/systemd/system/${service_name}"
    fi
    if [ -f "$file" ] ;then
        return 0
    else
        return 1
    fi
}

:<<!
* @description: Check if the given systemd service is running
* @param: service_name The systemd service name needs to be checked
* @return: 0|1
!
systemd_service_running()
{
    local service_name=$1
	systemctl is-active --quiet "${service_name}"
}

:<<!
* @description: Check the inexistent rpm packages
* @param: rpms The rpm package list needs to be checked.(for example: "make zlib-devel readline-devel")
* @return: string Inexistent rpm list
!
get_inexistent_rpms() {
    local rpms=$*
    j=0

    for i in ${rpms}
    do
        if [[ -z $(rpm -qa "$i") ]]; then
            inexistent_rpms[$j]=$i
            ((j++))
        fi

    done

    str=''
    for i in ${inexistent_rpms[@]};do 
        str="${str} $i" 
    done
    echo $str
}

:<<!
* @description: Check if a MongoDB binary version exists
* @param: version string
* @return: 0|1
!
mongo_exists()
{
	local version=$1
	local result=$(mongo --version | grep "${version}")
	
	if [[ -n "${result}" ]]; then
		return 0
	else
		return 1
	fi
}