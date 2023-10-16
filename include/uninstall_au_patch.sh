#!/bin/bash 
# IEVersion: 10.1.0

function uninstall_au_patch() {
	function init_variable() {
		SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
		cd "$SCRIPT_PATH" || return 1
	
		umask 022
		
		compath="/usr/share"
		aucpath="${compath}/auclient"
		#info_logging "Setting aucpath to $aucpath "
		allpackage="False"
		exitflag="False"
		FolderName=$(echo "$componentName" | sed -e 's/\(.*\)/\L\1/')	
				
		return 0
	}

	function check_pattern() {
		local flist
		local i
	
		version="$1"
		IFS='_'
		read -ra flist <<< "$version"
		if [ "${#flist[@]}" != 4 ]; then
			return 1
		fi
	
		re='^[0-9]+$'
		for((i=0;i<"${#flist[@]}";i++)); do
			#info check_pattern $i   ${flist[i]}
			if [[ "${flist[i]}" =~ $re ]]; then
				continue
			else
			#	info "${flist[i]}" is not a number
				return 1	
			fi
		done
		return 0
	}

	function get_currentversion() {
		if [[ ! -f "/usr/share/auclient/current.version" ]]; then
			return 1
		fi
		curversion=`cat /usr/share/auclient/current.version`
		curversion=`echo ${curversion}|sed 's/ //g'`
		if [ $? -ne 0 ]; then
			return 1
		fi
	
		return 0
	}

	function compare_version() {
		local version
		local vlist
		local mlist	
		local i
	
		version="$1"
		IFS='_'
		read -ra vlist <<< "$version"
		read -ra mlist <<< "$curversion"
		#echo "${mlist[@]}    ${vlist[@]}"
		#only compare the first 2 version numbers.
		for ((i=0;i<2;i++)); do
			if [ ${mlist[i]} -gt ${vlist[i]} ]; then
				info_logging "${mlist[i]} is greater than ${vlist[i]}"
				return 1
			fi

			if [ ${mlist[i]} -lt ${vlist[i]} ]; then
				info_logging "${mlist[i]} is less than ${vlist[i]}"
				return 0
			fi		
	
		done
	
		return 0
	}

	function sort_list() {
		local str1
		local str2
		local tmp
		local array5
		local array6
		local packageType
		local m 
		local j

		swapped="true"
		#info "${Patch_Version_List[@]}"
		while [ "${swapped}" == "true" ]; do
			swapped="false"
			for ((m=0;m<"${#Patch_Version_List[@]}";m++)); do
				str1="${Patch_Version_List[m]}"
				str2="${Patch_Version_List[m+1]}"
			
				if [[ "${#str1}" -eq 0 || "${#str2}" -eq 0 ]]; then
					break	
				fi
			
				IFS='_'
				read -ra array5 <<< "$str1"
				read -ra array6 <<< "$str2"
			
				for ((j=0;j<"${#Patch_Version_List[@]}";j++)); do
					#info "${array5[j]}"  and  "${array6[j]}"
					if [[ "${array5[j]}" -gt "${array6[j]}" ]]; then
						tmp="${Patch_Version_List[m]}"
						Patch_Version_List[m]="${Patch_Version_List[m+1]}"
						Patch_Version_List[m+1]="${tmp}"
						#info "${array5[j]}" is greater than "${array6[j]}"	
						swapped="true"
						break
					fi
				
					if [[ "${array5[j]}" -lt "${array6[j]}" ]]; then
						#info "${array5[j]}" is less than "${array6[j]}"
						break
					fi					
				done
			done
			#echo "${Patch_Version_List[@]} ${swapped}"
		done
		return 0
	}

	function get_pathon_bin() {
		local pbinpath
	
		pbinpath=$1
		pbpath=$(ls "${pbinpath}" |grep python|grep  [0-9]$ |sort |tail -1)
		pbpath=$(echo $pbpath|tr -d '\n'|tr -d '\r'|tr -d ' ')
		if [ $? -ne 0 ]; then
			error_logging "Failed to get pythong exe file."
			return 1
		fi
		info_logging "The latest python exe file is ${pbpath}"
		return 0	
	}




	local length 
	local pathonBinPath
	local pathonScriptPath	
	local packageHome
	local folder
	local n 
	local num
	local lastpackagetype
	
	componentName="$1"
		
	componentlist=("Mongodb" "License" "ElasticSearch" "Sentinel" "Redis" "RabbitMQ" "FrontServer" "ServiceMonitorAgent")

	if [[ ! "${componentlist[@]}" =~ "${componentName}" ]]; then
		error_logging "The entered component is not in the list of [  ${componentlist[@]} ] , try again please."
		return 1
	fi 
	
	init_variable
	if [ $? -ne 0 ]; then
		error_logging "Uninstallation aborted"
		return 1
	fi
	info_logging "AUClient path is ${aucpath}"
	
	if [ ! -d "${aucpath}" ]; then
		info_logging "Service Monitor Agent is not installed."
		return 1
	fi
		
	Patch_Version_List=()
	versionlist=()
	for folder in `ls /usr/share/auclient`; do
		if [[ -d "/usr/share/auclient/${folder}" ]]; then
			versionlist=("${versionlist[@]}" "${folder}")
		else
			info_logging "${folder} is not a folder."
		fi
		#echo "${versionlist[@]}"
	done

	#echo "${#versionlist[@]}"
	for((n=0;n<"${#versionlist[@]}";n++)); do
		#info_logging "version is n=$n  ${versionlist[n]}"
		check_pattern "${versionlist[n]}"
		if [ $? -eq 0 ]; then
			Patch_Version_List=("${Patch_Version_List[@]}" "${versionlist[n]}")
			#info "${versionlist[n]} is a patch folder"
		fi
		#echo "$n ${versionlist[n]} ${versionlist[@]}  ${Patch_Version_List[@]}"
	done
	#echo "Begining of sorting ${Patch_Version_List[@]}"

	sort_list
	
	#echo "Ending of sorting ${Patch_Version_List[@]}"
	num="${#Patch_Version_List[@]}"
	if [[ ${num} -gt 1 ]] && [[ "$2" == "notallintwo" ]]; then
		
		while true; do
			read -p "It is not recommended to uninstall single NetBrain component which may result in failure on performing system update. Please make sure all the components are uninstalled.Are you sure you want to continue (yes/no)? [no] " input
			if [[ "${input}" == "" ]]; then
				input="n"
			fi
			answer=$(checking2_yesno "${input}" "input")
			if [[ "${answer}" == "y" || "${answer}" == "n" ]]; then
				break
			fi
		done
		if [[ "${answer}" == "n" ]]; then
			info_logging "Exiting with error code 99..."
			info_logging "The uninstallation has been canceled by client."
			return 99
		fi
	fi
	
	if [ ${num} -eq 1 ]; then
		info_logging "No AutoUpdate patch is detected, exiting uninstall_au_patch..."
		return 1
	fi
	
	let num=num-1
	lastpackagetype=100
	
	#get_currentversion
	#if [ $? -ne 0 ]; then
	curversion=${Patch_Version_List[num]}
	info_logging "The current version is ${Patch_Version_List[num]}"
	#fi
	
	while [ ${num} -ge 0 ]; do
		get_pathon_bin "${aucpath}/${Patch_Version_List[num]}/python/bin"	
		if [ $? -ne 0 ]; then
			error_logging "Failed to get python exe file, skipping this version ${Patch_Version_List[num]}"
			let num=num-1
			continue
		fi
		pathonBinPath="${aucpath}/${Patch_Version_List[num]}/python/bin/${pbpath}"
		info_logging "pathon bin path is ${pathonBinPath}"
		APP_TOML_PATH="${aucpath}/${Patch_Version_List[num]}/autoupdate/conf/app.toml"
		info_logging "APP_TOML_PATH is ${APP_TOML_PATH} and the related patch version is ${Patch_Version_List[num]}."
		packageHome=$(cat "${APP_TOML_PATH}"|grep "^data_home ="|cut -d '=' -f 2)
		#info_logging "The packageHome is ${packageHome} and the related patch version is ${Patch_Version_List[num]}."
		
		packageHome=$(echo ${packageHome} | sed "s/\/\//\//g")
		packagehome=$(echo ${packageHome} | sed "s/'//g")
		packagehome=$(echo ${packagehome}|tr '\n' ' ')
		packagehome=$(echo $packagehome|tr -d '\n'|tr -d '\r'|tr -d ' ')
		info_logging "The package home is ${packagehome}/package"
		componentName="${componentName// /}"
		info_logging "The componentName is ${componentName}"
		pathonScriptPath="${packagehome}/package/client/${Patch_Version_List[num]}/${componentName}/Actions/Uninstallation/uninstall.py"
		info_logging "The pathon script path is ${pathonScriptPath}"
		info_logging "The pathon bin path is ${pathonBinPath} and the related patch version is ${Patch_Version_List[num]}."
		if [ ! -f "${pathonScriptPath}" ]; then
			exitflag="True"
			info_logging "${pathonScriptPath} does not exist, skipping this version ${Patch_Version_List[num]}"
			let num=num-1
			continue
		fi
		
		compare_version  "${Patch_Version_List[num]}"
		if [ $? -ne 0 ]; then
			exitflag="True"
			info_logging "exitflag is ${exitflag}, skipping this version ${Patch_Version_List[num]}"
			let num=num-1
			continue	
		else
			exitflag="False"
			info_logging "The exitflag is ${exitflag}"
		fi
		
		metafilePath="${packagehome}/client/${Patch_Version_List[num]}/metafile.toml"
		info_logging "The meata file path is ${metafilePath} and the patch version is ${Patch_Version_List[num]}"
		ls -lrt "${metafilePath}"
		info_logging "The exitflag is ${exitflag}"
		if [[ -f "${metafilePath}" ]]; then
			packageType=$(cat "${metafilePath}"|grep "^PackageType ="|cut -d '=' -f 2)
			info_logging "PackageType is  $packageType"
			if [[ "${packageType}" =~ "0" ]]; then
				allpackage="True"
				if [ ${lastpackagetype} -eq 100 ]; then
					lastpackagetype=0
				fi
				"${pathonBinPath}"   "${pathonScriptPath}" 
				if [ $? -ne 0 ]; then
					error_logging "Failed to execute uninstall.py"
				else
					info_logging "Succeeded in executing uninstall.py"
				fi
			elif [[ "${packageType}" =~ "2" ]]; then
				if [ ${lastpackagetype} -eq 100 ]; then
                                        lastpackagetype=2
					"${pathonBinPath}"   "${pathonScriptPath}"
	                                if [ $? -ne 0 ]; then
       	                        	         error_logging "Failed to execute uninstall.py"
                                	else
                                       		 info_logging "Succeeded in executing uninstall.py"
                                	fi
                                fi
			else
				if [ ${lastpackagetype} -eq 100 ]; then
                                        lastpackagetype=1
                                fi
				if [ "${allpackage}" == "False" ]; then

					"${pathonBinPath}"   "${pathonScriptPath}" 
					if [ $? -ne 0 ]; then
						error_logging "Failed to exeute uninstall.py"
					else
						info_logging "Succeeded in executing uninstall.py"
					fi
				
				fi
					
			fi
	
		else
			info_logging "The metafile does not exist, skipping this version ${Patch_Version_List[num]} "
	
		fi
		let num=num-1
	done

}

