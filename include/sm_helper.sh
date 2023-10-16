#!/bin/bash

#############################################################
## NOTE: This the property of NetBrain, Inc.               ## 
##       Customer shall not modify this script.            ## 
#############################################################

PORT_LIST=()		

function getInput()
{
	local input

	while true; do
		if [[ "$2" == "password" || "$2" == "espassword" ]]; then
			read -sp "$1" input
		else
			read -p "$1" input
		fi

		if [[ "${input}" == "" ]]; then
			break
		fi

		 
		case "$2" in
		"path") 
			validatePath "${input}" 
			[ $? -eq 0 ] && break
			;;
		"yesno") 
			answer=$(validateYesNo "${input}")
			if [ $? -eq 0 ]; then
				input="${answer}"
				break
			else
				echo >&2 "${answer}"
				continue
			fi
			;;
		"username") 
			validateCredentials "username" "${input}" 
			[ $? -eq 0 ] && break
			;;
		"password") 
			validateCredentials "password" "${input}" 
			[ $? -eq 0 ] && break
			;;
		esac
	done
	echo "${input}";
}

function validatePath()
{
	checking_customized_path "$1"
	if [ $? -ne 0 ]; then
		echo >&2 "$(get_last_error) "
		return 1
	fi
	checking_lsattr "$1"
	if [ $? -ne 0 ]; then
		echo >&2 "$(get_last_error) "
		return 1
	fi

	return 0
}

function validateCredentials()
{
	if [[ "$1" == "password" ]]; then
		checking_password "$2"
	else
		checking_username "$2"
	fi
	
	if [ $? -ne 0 ]; then
		echo >&2 -e "\r\n$(get_last_error) "
		return 1
	fi
	return 0	
}

function validateYesNo()
{
	checking2_yesno "$1"
}

SM_input_check_confirm()
{	
	echo "Configuring Service Monitor Agent ..." 
	echo "The values in brackets are the default values of the parameters. To keep the default value for the current parameter, press the Enter key." 

	local SETUP_CONFIG_PATH="$1"

	confirm="n"

	while [[ "${confirm}" == "n" ]]; do
		server_monitor_URL=""

		test="n"
		while [ "${test}" == "n" ]; do
			read -p "Please enter the URL (must end with /) to call NetBrain Web API service for the Service Monitor Agent [http(s)://<IP address or hostname of NetBrain Application Server>/]: " server_monitor_URL
			is_valid_url "${server_monitor_URL}"
			if [ $? -ne 0 ]; then
				error "The URL is invalid. Please make sure the URL starts with http(s):// and ends with /."
			else
				test="y"
			fi
		done;

		server_monitor_URL="${server_monitor_URL}ServicesAPI"
		ISHTTPS="n"

		testURL=$(echo "$server_monitor_URL" | cut -d ":" -f1)
		testURL=$(echo "$testURL" | grep -i "https")
		if [ -n "${testURL}" ]; then
			ISHTTPS="y"
		fi

		echo -e "\r"
		
		test="n"
		while [[ "${test}" == "n" ]]; do

			password=$(getInput "Please enter the API Key to be used to communicate with application server which must be the same as the one created on Web API server: " "password")
			while [[ "$password" = "" ]] || [[ "${password}" == \#* ]] || [[ "${password}" == \!* ]]; do
			   echo -e "\r"
			   echo "The API Key should not be empty and the first character of password cannot be ! or #."
			   password=$(getInput "Please enter the API Key to be used to communicate with application server which must be the same as the one created on Web API server: " "password")
			done

			echo -e "\r"

			read -sp "Please re-enter API key to confirm: " passwordconfirm 

			if [[ "${passwordconfirm}" == "${password}" ]]; then
				test="y"
			else
				echo -e "\r"
				echo "The API keys you entered do not match."
			fi
		done;

		echo -e "\r"

		dataPath1="/usr/share"

		freespaceinMB=$(get_disk_available_size "${dataPath1}")

		if [ "$freespaceinMB" -le "10240" ]; then
			answer=$(getInput "The free space in the ${dataPath1} is less than 10GB. It may result in insufficient disk space after a period of use. Do you want to continue (yes/no)? [no] " "yesno")
			if [[ "${answer}" == "" || "${answer}" == "n"  ]]; then
				return 1
			fi
		fi
		
		logPath0="/var/log/netbrain/nbagent"

		test="n"
		while [ "${test}" == "n" ]; do
			logPath=$(getInput "Please enter a log path for NetBrain Service Monitor Agent [${logPath0}]: " "path")
			test="y"

			if [[ "${logPath}" == "" ]]; then
				logPath="${logPath0}"
			fi

			checking_path_is_file "${logPath}"
			if [ $? -eq 0 ]; then
				echo "Path ${logPath} is an existing file."
				test="n"
			fi

			if [ "${test}" == "y" ]; then
				validatePath "${logPath}"
				if [ $? -ne 0 ]; then
					test="n"
				fi
				freespaceinMB=$(get_disk_available_size "${logPath}")

				if [ "$freespaceinMB" -le "10240" ]; then
					answer=$(getInput "The free space in the path is less than 10GB. It may result in insufficient disk space after a period of use. Do you want to continue (yes/no)? [no] " "yesno")
					if [[ "${answer}" == "" || "${answer}" == "n"  ]]; then
						test="n"
					fi
				fi
			fi
		done;
		
		if [[ "${ISHTTPS}" == "y" ]]; then
			CAverify10="no"
			caverify=$(getInput "Whether to enable verifying Certificate Authority (CA) of certificates used by Web API server for Service Monitor Agent? [$CAverify10]: " "yesno")

			if [[ "${caverify}" = "yes" || "${caverify}" = "y" ]]; then
			   caverify="yes"
			else
			   caverify="no"
			fi

			if [[ "${caverify}" == "yes" ]]; then

				capath=""
				while [[ "${capath}" == "" ]]; do
					read -p "Please enter the name and storage path of the Certificate Authority file: " capath
				done

				while [[ ! -f "${capath}" ]]; do
					read -p "The Certificate Authority file [$capath] does not exist, please enter again: " capath
				done
			
				local parent="$(dirname "$capath")"
				chmod -R +r "$capath"
			fi
		
			#usessl0="no"
			#usessl=$(getInput "Encrypt connections to AutoUpdate Server. UseSSL is yes only if SSL is enabled on AutoUpdate Server? [$usessl0]: " "yesno")

			#if [[ "${usessl}" = "yes" || "${usessl}" = "y" ]]; then
			#   usessl="yes"
			#else
			#   usessl="no"
			#fi

			#if [[ "${usessl}" == "yes" ]]; then

			#	CAverify10_au="no"
			#	caverify_au=$(getInput "Whether to enable verifying CA of certificates used by AutoUpdate Server? [$CAverify10_au]: " "yesno")

			#	if [[ "${caverify_au}" = "yes" || "${caverify_au}" = "y" ]]; then
			#		caverify_au="yes"
			#	else
			#		caverify_au="no"
			#	fi

			#	if [[ "${caverify_au}" == "yes" ]]; then

			#		capath_au=""
			#		while [[ "${capath_au}" == "" ]]; do
			#			read -p "Please enter the name and storage path of the Certificate Authority file: " capath_au
			#		done

			#		while [[ ! -f "${capath_au}" ]]; do
			#			read -p "The Certificate Authority file [$capath_au] does not exist, please enter again: " capath_au
			#		done
			
			#		local parent="$(dirname "$capath_au")"
			#		chmod -R +r "$capath_au"
			#	fi
			#fi
		fi

		printf "\n"
		printf "NetBrain Web API service URL: \t%s\n" "${server_monitor_URL}"
		printf "API key: \t\t%s\n" "******"
		printf "NetBrain Service Monitor Agent LogPath: \t%s\n" "${logPath}"
		if [[ "${caverify}" = "yes" ]]; then
			printf "Certificate Authority verification: \t\tyes\n"
			printf "Certificate Authority file: \t${capath}\n"
		else
			printf "Certificate Authority verification: \t\tno\n"
		fi
		#if [[ "${usessl}" = "yes" ]]; then
		#	printf "AutoUpdate uses SSL: \t\tyes\n"
		#	if [[ "${caverify_au}" = "yes" ]]; then
		#		printf "CA_Verify_AU: \t\tyes\n"
		#		printf "Certificate Authority path: \t${capath_au}\n"
		#	else
		#		printf "CA_Verify_AU: \t\tno\n"
		#	fi
		#else
		#	printf "AutoUpdate uses SSL: \t\tno\n"
		#fi
		printf "\n"

		
		confirm=$(getInput "Do you want to continue using these parameters? [yes] " "yesno")

		if [[ "${confirm}" == "no" ]]; then
		   confirm="n"
		fi
	done;
	
	set_ini "$SETUP_CONFIG_PATH" "" "Server_Url" "${server_monitor_URL}"
	set_ini "$SETUP_CONFIG_PATH" "" "Server_Key" "${password}"
	set_ini "$SETUP_CONFIG_PATH" "" "LogPath" "${logPath}"
	if [[ "${caverify}" = "yes" ]]; then
		set_ini "$SETUP_CONFIG_PATH" "" "CA_Verify" "${caverify}"
		set_ini "$SETUP_CONFIG_PATH" "" "CertAuth" "${capath}"
	fi
	#set_ini "$SETUP_CONFIG_PATH" "" "UseSSL" "${usessl}"
	#if [[ "${usessl}" = "yes" ]]; then
	#	set_ini "$SETUP_CONFIG_PATH" "" "CA_Verify_AU" "${caverify_au}"
	#	if [[ "${caverify_au}" = "yes" ]]; then
	#		set_ini "$SETUP_CONFIG_PATH" "" "CertAuth_AU" "${capath_au}"
	#	fi
	#fi
}

SM_input_check_confirm_for_upgrade()
{	
	local SETUP_CONFIG_PATH="$1"

	confirm="n"

}
