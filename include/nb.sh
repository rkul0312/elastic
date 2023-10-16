#!/bin/bash

#################################################
# @param $1: None
# @echo: log root path
#################################################
nb_log_path() {
	echo "/var/log/netbrain/installationlog"
}

#################################################
# @echo: uninstal root path
#################################################
nb_uninstall_path() {
	echo "/usr/lib/netbrain/installer"
}


#################################################
# @echo: install log file name
#################################################
nb_install_log_name() {
	echo "install.log"
}

#################################################
# @echo: uninstall log file name
#################################################
nb_uninstall_log_name() {
	echo "uninstall.log"
}

#################################################
# @echo: upgrade log file name
#################################################
nb_upgrade_log_name() {
	echo "upgrade.log"
}

#################################################
# @echo: uninstall shell file name
#################################################
nb_uninstall_name() {
	echo "uninstall.sh"
}

#################################################
# @param $1: component name
# @echo: install log file name
#################################################
nb_comp_install_log_filepath() {
	echo "$(nb_log_path)/$1/$(nb_install_log_name)"
}

#################################################
# @param $1: component name
# @echo: uninstall log file name
#################################################
nb_comp_uninstall_log_filepath() {
	echo "$(nb_log_path)/"$1"/$(nb_uninstall_log_name)"
}

#################################################
# @param $1: component name
# @echo: upgrade log file name
#################################################
nb_comp_upgrade_log_filepath() {
	echo "$(nb_log_path)/"$1"/$(nb_upgrade_log_name)"
}

#################################################
# @param $1: component name
# @echo: uninstall shell file name
#################################################
nb_comp_uninstall_filepath() {
	echo "$(nb_uninstall_path)/"$1"/$(nb_uninstall_name)"
}

:<<!
 @param $1: info callback
 @param $2: rpmrootpath
 @param $3: array list [rpm name, flag, rpm file name]
		flag 1, yum
		flag 2, local check os
		flag 3, local - uncheck os
		flag 4, yum-> local check os
		flag 5, yum-> local uncheck os 
 @echo: error message
!

nb_install_depend_rpmlist(){
	local info_callback=$1
	local rpmrootpath=$2
	shift
	shift
	local rpmlist=("$@")
	local len=${#rpmlist[@]}
	local looplen=$(($len/3))

	local osname=$(get_os)
	
	local ospath
	if [ "${osname}" == "centos" ]; then
		ospath="centos"
	elif [ "${osname}" == "rhel" ]; then
		ospath="redhat"
	elif [ "${osname}" == "almalinux" ]; then
		ospath="almalinux"
	elif [ "${osname}" == "rockylinux" ]; then
		ospath="rockylinux"
	elif [ "${osname}" == "ol" ]; then
		ospath="ol"
	elif [ "${osname}" == "amzn" ]; then
		ospath="amzn"
	else
		set_last_error "Unsupported OS "${osname}""
		return 1
	fi
	
	for(( i=0; i<$looplen; i++));
	do
		local pkgname=${rpmlist[$(($i*3))]}
		
		#check package exists
		rpm -qa ${pkgname}|grep "${pkgname}" >/dev/null 2>&1
		if [ $? -eq 0 ]; then
			$info_callback "${pkgname} had already been installed."
			continue
		fi		
		
		#flag 1, yum
		#flag 2, local check os
		#flag 3, local - uncheck os
		#flag 4, yum-> local check os
		#flag 5, yum-> local uncheck os
		
		local flag=${rpmlist[$(($i*3+1))]} 
		
		
		#yum install
		if [ $flag -eq 1 ] || [ $flag -eq 4 ] || [ $flag -eq 5 ] ; then
			$info_callback "Yum installing ${pkgname}." 
			yum -y install "${pkgname}"
			if [ $? -eq 0 ]; then 
				continue
			fi
			
			if [ $flag -eq 1 ]; then
				set_last_error "Failed to install ${pkgname}." 
				return 1
			fi
		fi
				
		#local install
		local pkgnamerpm=${rpmlist[$(($i*3+2))]}
			
		local pckagepath
		if [ ${flag} -eq 2 ] || [ ${flag} -eq 4 ]; then
			pckagepath="${rpmrootpath}/${ospath}/${pkgnamerpm}"
		else
			pckagepath="${rpmrootpath}/${pkgnamerpm}"
		fi
		
		$info_callback "Installing local package ${pckagepath}" 
		rpm -ivh "${pckagepath}"
		if [ $? -ne 0 ]; then
			set_last_error "Failed to install ${pkgname}." 
			return 1
		fi
		$info_callback "Successfully installed ${pkgname}." 
	done
}

nb_backup_uninstall_files(){
	installDir=$1
	uninstallPath=$2
	
	rm -rf "${uninstallPath}/include"
    if [ -e "${uninstallPath}/include" ]; then
        set_last_error "Failed to remove ${uninstallPath}/include."
        return 1
    fi	
	
	mkdir -p "${uninstallPath}/include"
    if [ $? -ne 0 ]; then
        set_last_error "Failed to create ${uninstallPath}/include."
        return 1
    fi
	
    yes|cp -rf "${installDir}/others/uninstall.sh" "${uninstallPath}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        set_last_error "Failed to save file uninstall.sh."
        return 1
    fi
	
	
    yes|cp -rf "${installDir}/include/." "${uninstallPath}/include/" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        set_last_error "Failed to save files in include folder."
        return 1
    fi	

	return 0
}

nb_remove_uninstall_files(){
	uninstallPath=$1
	
	rm -rf "${uninstallPath}/include"
    if [ -e "${uninstallPath}/include" ]; then
        set_last_error "Failed to remove ${uninstallPath}/include"
        return 1
    fi	
	
    rm -rf "${uninstallPath}/uninstall.sh"
    if [ -e "${uninstallPath}/uninstall.sh" ]; then
        set_last_error "Failed to remove file ${uninstallPath}/uninstall.sh."
        return 1
    fi

	if [ -f "${uninstallPath}/uninstall.sh.backup" ]; then
		rm -rf "${uninstallPath}/uninstall.sh.backup"
	fi

	if [ ! "$(ls -A "${uninstallPath}")" ]; then
    	rm -rf "${uninstallPath}"
	fi
	
	return 0
}

nb_backup_release_info_file(){
	installDir=$1
	targetPath=$2
	
	info_file="fix_releaseinfo.json"
	
    if [ -f "${targetPath}/${info_file}" ]; then
		rm -rf "${targetPath}/${info_file}"
		if [ -e "${targetPath}/${info_file}" ]; then
			set_last_error "Failed to remove file ${targetPath}/${info_file}."
			return 1
		fi
    fi	

	if [ ! -d "${targetPath}" ]; then
		mkdir -p "${targetPath}"
		if [ $? -ne 0 ]; then
			set_last_error "Failed to create ${targetPath}."
			return 1
		fi
    fi
	
    yes|cp -f "${installDir}/${info_file}" "${targetPath}"
    if [ $? -ne 0 ]; then
        set_last_error "Failed to save file ${info_file}."
        return 1
    fi

	chmod -x "${targetPath}/${info_file}"
	
	return 0
}

nb_remove_release_info_file(){
	targetPath=$1

	info_file="fix_releaseinfo.json"

	if [ -f "${targetPath}/${info_file}" ]; then
		rm -rf "${targetPath}/${info_file}"
		if [ -f "${targetPath}/${info_file}" ]; then
			set_last_error "Failed to remove ${targetPath}/${info_file}"
			return 1
		fi
    fi	

	return 0
}

nb_is_8x() {
	if /bin/mongo --version | grep -w "v4.0.6" > /dev/null 2>&1 ; then
		return 0
	else
		return 1
	fi
}

nb_restore_setup_conf() {
	path=$1

	if [ -f "${path}/others/setup.conf.template" ]; then
		if [ -f "${path}/config/setup.conf" ]; then
			rm -f "${path}/config/setup.conf"
		fi
		yes|cp -f "${path}/others/setup.conf.template" "${path}/config/setup.conf"

		if [ $? -ne 0 ]; then
			set_last_error "Failed to restore file ${dest}/setup.conf."
			return 1
		fi

		return 0
	else
		return 1
	fi
}

nb_remove_setup_conf() {
	path=$1

	if [ -f "${path}/setup.conf" ]; then
		rm -f "${path}/setup.conf"
	fi
}

nb_is_ver_from_releaseinfo() {
	local SOFTWARE_VERSION
	local path=$1
	local version=$2
	if [[ -f "${path}" ]]; then
		SOFTWARE_VERSION=$("$(dirname "${BASH_SOURCE[0]}")/yq" r "${path}" "SoftwareVersion")
		if [[ ${SOFTWARE_VERSION} == "${version}" ]]; then 
			return 0
		fi
	fi
	return 1
}

nb_is_ver_starts_in_releaseinfo() {
	local SOFTWARE_VERSION
	local path=$1
	local version=$2
	if [[ -f "${path}" ]]; then
		SOFTWARE_VERSION=$("$(dirname "${BASH_SOURCE[0]}")/yq" r "${path}" "SoftwareVersion")
		if [[ "${SOFTWARE_VERSION}" == "${version}"* ]]; then 
			return 0
		fi
	fi
	return 1
}

nb_is_801_from_releaseinfo() {
	local path=$1
	nb_is_ver_from_releaseinfo "${path}" "8.0.01"
}

nb_is_802_from_releaseinfo() {
	local path=$1
	nb_is_ver_from_releaseinfo "${path}" "8.0.2"
}

nb_is_803_from_releaseinfo() {
	local path=$1
	nb_is_ver_from_releaseinfo "${path}" "8.0.3"
}

nb_is_1000_from_releaseinfo() {
	local path=$1
	nb_is_ver_from_releaseinfo "${path}" "10.0.0"
}

nb_is_1001_from_releaseinfo() {
	local path=$1
	nb_is_ver_from_releaseinfo "${path}" "10.0.10"
}

nb_is_1010_from_releaseinfo() {
	local path=$1
	nb_is_ver_from_releaseinfo "${path}" "10.1.0"
	if [[ $? -eq 0 ]]; then
		return 0
	else
		nb_is_ver_from_releaseinfo "${path}" "10.1.1"
		if [[ $? -eq 0 ]]; then
			return 0
		else
			nb_is_ver_from_releaseinfo "${path}" "10.1.3"
			if [[ $? -eq 0 ]]; then
				return 0
			else
				nb_is_ver_from_releaseinfo "${path}" "10.1.5"
				if [[ $? -eq 0 ]]; then
					return 0
				fi
			fi
		fi
	fi
	return 1
}

nb_is_1110_from_releaseinfo() {
	local path=$1
	nb_is_ver_from_releaseinfo "${path}" "10.1.9"
	if [[ $? -eq 0 ]]; then
		return 0
	else
		nb_is_ver_from_releaseinfo "${path}" "10.1.0"
		if [[ $? -eq 0 ]]; then
			return 0
		else
			nb_is_ver_from_releaseinfo "${path}" "10.1.1"
			if [[ $? -eq 0 ]]; then
				return 0
			else
				nb_is_ver_from_releaseinfo "${path}" "10.1.3"
				if [[ $? -eq 0 ]]; then
					return 0
				else
					nb_is_ver_from_releaseinfo "${path}" "10.1.5"
					if [[ $? -eq 0 ]]; then
						return 0
					fi
				fi
			fi
		fi
	fi
	return 1
}

#################################################
# @param $1: MONITOR_SCRIPTS_PATH
# @echo: Install Service Monitor Agent
#################################################
nb_install_monitor(){
	local scripts_path=$1
	
	"${scripts_path}"/install.sh
	
	if [ $? -ne 0 ]; then
		set_last_error "Failed to install Service Monitor Agent." 
		return 1
	fi	
	return 0
}

#################################################
# @param $1: MONITOR_SCRIPTS_PATH
# @echo: Upgrade Service Monitor Agent
#################################################
nb_upgrade_monitor(){
	local scripts_path=$1
	
	"${scripts_path}"/upgrade.sh
	
	if [ $? -ne 0 ]; then
		set_last_error "Failed to upgrade Service Monitor Agent." 
		return 1
	fi	

	return 0
}

#################################################
# @param $1: component name
# @return: 0 - allowed; 1 - not allowed 
#################################################
nb_is_upgrade_allowed() {

	local fix_release_info=$1


	return 0
}
