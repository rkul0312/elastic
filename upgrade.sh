#!/bin/bash
# IEVersion: 10.1.0
# shellcheck source="$SCRIPT_PATH/include/source.sh"
# shellcheck disable=SC2104,SC2155,SC2162,SC2181,SC1091

init_variable() {
	SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	cd "$SCRIPT_PATH" || return 1

	umask 022
	#looptag=true
	
	source ./include/source.sh
	PRODUCT_VERSION="11.0"
	SOFTWARE_VERSION="11.0"
	MONITOR_VERSION="11.1"

	#PROCESS="upgrading"
	LOG_PATH="/var/log/netbrain/installationlog/elasticsearch"
	#INSTALL_LOG="${LOG_PATH}/upgrade.log"
	SERVICE_NAME="elasticsearch"
	COMPONENT_NAME="Elasticsearch"
	RPM_NAME="elasticsearch-oss"
	ES_Version="6.8.23"
	INSTALL_PATH="/usr/share/elasticsearch"
	FOLDER_NAME="elasticsearch"
	CONFIG_PATH="/etc/elasticsearch"
	UNINSTALL_PATH="$(nb_uninstall_path)/${FOLDER_NAME}"
	UNINSTALL_NAME="uninstall.sh"
	FIX_RELEASE_INFO="/usr/share/${FOLDER_NAME}/fix_releaseinfo.json"
	AllInTwo="false"
	ReplaceAccount="false"
	mongodb_username=""
	mongodb_password=""
	flag="false"
	match="no"
	jksused=""
	jksflag="jksfalse"
	#pluginspath="$INSTALL_PATH/plugins/search-guard-6"
    #SgInternalUsers="$pluginspath/sgconfig/sg_internal_users.yml"
	if [ -f "/etc/sysconfig/elasticsearch" ]; then
		jdkpath=`cat /etc/sysconfig/elasticsearch |grep -v '^#'| grep JAVA_HOME|head -1|cut -d '=' -f 2`
		if [ $? -ne 0 ]; then
			error "Failed to retrieve JAVA_HOME from /etc/sysconfig/elasticsearch file."
			return 1
		fi
	
		export JAVA_HOME=${jdkpath##*( )}
		info "JAVA_HOME has been set to ${JAVA_HOME}."
	fi
	
	#initializing the parameters used to access the ES
	PRIVATEKEY4upgrade=""
	CERTIFICATE4upgrade=""
	CERTAUTH4upgrade=""
	OLD_PRIVATEKEY4upgrade=""
	OLD_CERTIFICATE4upgrade=""
	OLD_CERTAUTH4upgrade=""
	OLD_USESSL4upgrade="false"
	
	if [ -n "$1" ]; then
		INSTALL_LOG="${1}"
		LOG_PATH=$(dirname "${INSTALL_LOG}")
	else
		INSTALL_LOG="$(nb_comp_upgrade_log_filepath $FOLDER_NAME)"
	fi

	UPGRADE_TEMP="${LOG_PATH}/upgrade_tmp"
	
	return 0
}


set_java_home() {
	 if [ -f "/etc/sysconfig/elasticsearch" ]; then
                jdkpath=`cat /etc/sysconfig/elasticsearch |grep -v '^#'| grep JAVA_HOME|head -1|cut -d '=' -f 2`
                if [ $? -ne 0 ]; then
                        error_logging "Failed to retrieve JAVA_HOME from /etc/sysconfig/elasticsearch file."
                        return 1
                fi

                export JAVA_HOME=${jdkpath##*( )}
                info_logging "JAVA_HOME has been set to ${JAVA_HOME}."
        fi
	return 0
}

check_certs() {
	if [[ "${jksflag}" == "jkstrue" ]]; then
		info_logging "jks is used, skipping checking certificates..."
		return 0
	fi
	checking_certificate "${LOG_PATH}/${CERTIFICATE}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The upgrading was aborted."
		return 1
	fi
	checking_certificate_key "${LOG_PATH}/${PRIVATEKEY}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The upgrading was aborted."
		return 1
	fi
	checking_certificate "${LOG_PATH}/${CERTAUTH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The upgrading was aborted."
		return 1
	fi
	info_logging "Finished checking the certificates, no issue found."
	return 0
}

comp_checking()
{
	return 0
}

comp_get_upgrade_status() {
	init_variable "${1}"
	collect_es_info
		

	OLD_INSTALL_PATH=$(get_ini "${UPGRADE_TEMP}" "" "-Des.path.home")
	
	

	if [ -z "${OLD_INSTALL_PATH}" ]; then
		grep "Starts and stops a single elasticsearch instance on this system" /etc/init.d/*
		if [ $? -ne 0 ] && [ ! -f /usr/lib/systemd/system/elasticsearch.service ]; then
			# Fresh install is required.
			info_logging "${COMPONENT_NAME} was not installed. Fresh installation is required. "
			return 1
		fi
	elif nb_is_1010_from_releaseinfo "${FIX_RELEASE_INFO}"; then
		# Same version; No upgrade required.
		info_logging "The latest version of ${COMPONENT_NAME} has been installed."
		return 2
	else
		# Upgrade is required
		info_logging "Old version of ${COMPONENT_NAME} was installed. An upgrade is required. "
		return 0
	fi
	
	return 0
}

comp_get_running_status() {
	init_variable "${1}"
	collect_es_info

	OLD_SERVICENAME=$(grep "\.pid" "${UPGRADE_TEMP}" | awk -F "/" '{print $NF}' | cut -d "." -f1)

	# Check if the service is running
	if systemctl status "${OLD_SERVICENAME}" --no-pager 2>&1 | grep running >/dev/null 2>&1; then
		info_logging "The service of ${COMPONENT_NAME} is running."
		return 0
	else
		info_logging "The service of ${COMPONENT_NAME} is not running."
		return 1
	fi
	
}

comp_upgrade() {
	init_variable "${1}"
	collect_es_info
	AllInTwo="true"

	OLD_INSTALL_PATH=$(get_ini "${UPGRADE_TEMP}" "" "-Des.path.home")
	
	
	
	if nb_is_1010_from_releaseinfo "${FIX_RELEASE_INFO}"; then
		info_logging "The latest version of ${COMPONENT_NAME} has been installed."
		return 2	
	else
		ReplaceAccount="true"
		get_old_setup_parameters "${2}"
		if [ $? -ne 0 ]; then
			return 1
		fi
		
		check_certs
		if [ $? -ne 0 ]; then
			return 1
		fi	
			
		conf_setting
		if [ $? -ne 0 ]; then
			return 1
		fi
		if [[ "${OLD_CLUSTERMEMBERS}" != "null" ]] && [[ "${jksflag}" == "jksfalse" ]]; then
			manage_shard_allocation disable
		fi
		uninstall_old_version
		if [ $? -ne 0 ]; then
			return 1
		fi
		
		install_new_version "${1}"
		if [ $? -ne 0 ]; then
			return 1
		fi

		set_java_home
		if [ $? -ne 0 ]; then
                        return 1
                fi

		
		if [ ${ReplaceAccount} == "true" ] && [ ${flag} == "true" ] && [ -n ${mongodb_username} ]; then
			OLD_USERNAME=${mongodb_username}
			OLD_PASSWORD=${mongodb_password}
			info_logging "Starting to use the new credential for the post processing..."
		fi

		if [[ "${OLD_CLUSTERMEMBERS}" != "null" ]] && [[ "${jksflag}" == "jksfalse" ]]; then
			manage_shard_allocation enable
		fi
		
		#if [[ "${jksflag}" == "jksfalse" ]]; then
		#	delete_old_index
		#fi
		
		set_user_creation_immutable
		 if [[ "${OLD_CLUSTERMEMBERS}" != "null" ]] && [[ "${jksflag}" == "jksfalse" ]]; then
                        check_health
                        if [[ "$clusterStatus" == "green" ]]; then
                                info_logging "Cluster status is $(green "green")."
                        fi
                        if [[ "$clusterStatus" == "error" ]]; then
                                error_logging "Cluster status is ${clusterStatus}."
                                return 1 
                        fi
         fi

		#if [[ "${OLD_USERNAME}" == "${tmpuser}" ]]; then
		if [ ${ReplaceAccount} == "true" ] && [ ${flag} == "true" ] && [ -n ${mongodb_username} ]; then
			info_logging "This is AllInTwo upgrade, there is no need to restore the previous account information."
			if [ -f "${LOG_PATH}/sg_internal_users.yml" ]; then
				rm -f "${LOG_PATH}/sg_internal_users.yml"
				info_logging "Succeeded in deleting ${LOG_PATH}/sg_internal_users.yml backup file."
			fi
		else
			if [[ "${jksflag}" == "jksfalse" ]]; then
				del_temp_user_restore_old_user
				if [ $? -ne 0 ]; then
					warn_logging "Failed to restore the previous account information."
					#return 1
				else
					info_logging "This is AllInTwo upgrade, but there is no valid account information in setup.conf file. Successfully restored the previous account information."
				fi
			fi
		fi

		return 0
	
	fi

}

preprocessing() {
	#init_variable
	#collect_es_info
		
	checking_root
	if [ $? -ne 0 ]; then
		error "$(get_last_error) The upgrading was aborted."
		return 1
	fi
		

	#checking_eula
	checking_date
	if [ $? -ne 0 ]; then
		error "$(get_last_error) The upgrading was aborted."
		return 1
	fi
	
	#os checking
	#checking_os
	#if [ $? -ne 0 ]; then
	#	error "$(get_last_error) The upgrading was aborted."
	#	return 1
	#fi
	
	
	#if [ ! -f "${INSTALL_LOG}" ]; then
	create_log_file "${INSTALL_LOG}"
	if [ $? -ne 0 ]; then
		error "$(get_last_error) The upgrading was aborted."
		return 1
	else
		info_logging "Creating upgrading log file $(green "SUCCEEDED")"
	fi
	#fi
	
	collecting_system_info
	collect_es_info
	
	#collect os log
	#collecting_system_info

	return 0
}

get_old_setup_parameters() {
	info_logging "Starting to get the previous installation parameters..."

	local SETUP_CONFIG_SRC_PATH="${1}"
	info_logging "${SETUP_CONFIG_SRC_PATH}"
	
	if [ -n "${SETUP_CONFIG_SRC_PATH}" ]; then
		cat ${SETUP_CONFIG_SRC_PATH} |grep -i username > /dev/null 2>&1
		if [ $? -eq 0 ]; then
			flag="true"
		fi
		#yes | cp -f "${SETUP_CONFIG_SRC_PATH}"  "/tmp/"
	fi
	
	OLD_CONFIG_PATH=$(get_ini "${UPGRADE_TEMP}" "" "-Des.path.conf")
	OLD_INSTALL_PATH=$(get_ini "${UPGRADE_TEMP}" "" "-Des.path.home")
	OLD_SERVICENAME=$(grep "\.pid" "${UPGRADE_TEMP}" | awk -F "/" '{print $NF}' | cut -d "." -f1)
	info_logging "old_servicename: ${OLD_SERVICENAME}, ${OLD_CONFIG_PATH}, ${OLD_INSTALL_PATH}."

	if [ -z "${OLD_INSTALL_PATH}" ]; then
		grep "Starts and stops a single elasticsearch instance on this system" /etc/init.d/*
		if [ $? -ne 0 ] && [ ! -f /usr/lib/systemd/system/elasticsearch.service ]; then
			# Fresh install is required.
			info_logging "${COMPONENT_NAME} was not installed. Fresh installation is required. "
			return 0
		else
			info_logging "The service of ${COMPONENT_NAME} is not running. Please start the service first."
			return 1
		fi
	#else
	#	if nb_is_1010_from_releaseinfo "${FIX_RELEASE_INFO}"; then
			# Same version; No upgrade required.
	#		info_logging "The latest version of ${COMPONENT_NAME} has been installed. The upgrading was aborted."
	#		return 2
	#	fi
	fi

	if [ -z "${OLD_CONFIG_PATH}" ]; then
		OLD_CONFIG_PATH="${OLD_INSTALL_PATH}/config"
	fi

	systemctl status "${OLD_SERVICENAME}" --no-pager >/dev/null 2>&1
	if [[ $? -eq 4 ]]; then
		error_logging "The service of ${COMPONENT_NAME} has not been installed on this machine. The upgrading was aborted."
		return 1
	fi
	#checking_systemd_not_exists "${OLD_SERVICENAME}" "${COMPONENT_NAME}"

	OLD_CONFIG_FILE="${OLD_CONFIG_PATH}"/elasticsearch.yml
	OLD_CLUSTERNAME=$(get_yaml "${OLD_CONFIG_FILE}" "[cluster.name]")
	OLD_NODENAME=$(get_yaml "${OLD_CONFIG_FILE}" "[node.name]")
	OLD_BINDIP=$(get_yaml "${OLD_CONFIG_FILE}" "[network.host]")
	OLD_BINDIP=$(echo "${OLD_BINDIP}" | sed 's/127.0.0.1//g')
	OLD_BINDIP=$(echo "${OLD_BINDIP}" | sed 's/localhost//g')
	OLD_BINDIP=$(echo "${OLD_BINDIP}" | sed 's/,//g')
	OLD_CLUSTERMEMBERS=$(get_yaml "${OLD_CONFIG_FILE}" "[discovery.zen.ping.unicast.hosts]")
	OLD_CIPHERS=$(get_yaml "${OLD_CONFIG_FILE}" "[searchguard.ssl.http.enabled_ciphers]")
	OLD_MASTERONLYNODE=$(get_yaml "${OLD_CONFIG_FILE}" "[node.data]")
	OLD_DATAPATH=$(get_yaml "${OLD_CONFIG_FILE}" "[path.data]")
	OLD_LOGPATH=$(get_yaml "${OLD_CONFIG_FILE}" "[path.logs]")

	OLD_PORT=$(get_yaml "${OLD_CONFIG_FILE}" "[http.port]")

	if [ "${OLD_MASTERONLYNODE}" = "false" ]; then
		OLD_MASTERONLYNODE="yes"
	else
		OLD_MASTERONLYNODE="no"
	fi


	info_logging "OLD_CONFIG_FILE: ${OLD_CONFIG_FILE}"

	if [[ "${OLD_CLUSTERMEMBERS}" != "null" ]]; then
		echo ClusterMembers="${OLD_CLUSTERMEMBERS}" >>"${UPGRADE_TEMP}"
		sed -i "s@=- @=@g" "${UPGRADE_TEMP}"
		sed -i ':t;N;s/\n/ /;b t' "${UPGRADE_TEMP}"
		sed -i "s@ - @,@g" "${UPGRADE_TEMP}"
		sed -i "s@ @\n@g" "${UPGRADE_TEMP}"
		OLD_CLUSTERMEMBERS=$(get_ini "${UPGRADE_TEMP}" "" ClusterMembers)
	fi
	
	if [[ "${OLD_CIPHERS}" != "null" ]]; then
		echo Ciphers="${OLD_CIPHERS}" > "${UPGRADE_TEMP}"
		sed -i "s@=- @=@g" "${UPGRADE_TEMP}"
		sed -i ':t;N;s/\n/ /;b t' "${UPGRADE_TEMP}"
		sed -i "s@ - @,@g" "${UPGRADE_TEMP}"
		sed -i "s@ @\n@g" "${UPGRADE_TEMP}"
		OLD_CIPHERS=$(get_ini "${UPGRADE_TEMP}" "" Ciphers)
	fi

	OLD_USESSL4upgrade=$(get_yaml "${OLD_CONFIG_FILE}" "[searchguard.ssl.http.enabled]")
	if [[ "${flag}" == "true" ]]; then
		OLD_USESSL=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "UseSSL")
		OLD_PRIVATEKEY_TMP=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "PrivateKey")
		
	else
		OLD_USESSL=$(get_yaml "${OLD_CONFIG_FILE}" "[searchguard.ssl.http.enabled]")
	fi

	if [[ "$OLD_USESSL" == "false" ]] || [[ "$OLD_USESSL" == "no" ]]; then
		usessl="no"
	else
		usessl="yes"
	fi
	
	#Retrieving the previous certifcates for accessing the ES afterwards
	PRIVATEKEY4upgrade=$(get_yaml "${OLD_CONFIG_FILE}" "[searchguard.ssl.http.pemkey_filepath]")
	CERTIFICATE4upgrade=$(get_yaml "${OLD_CONFIG_FILE}" "[searchguard.ssl.http.pemcert_filepath]")
	CERTAUTH4upgrade=$(get_yaml "${OLD_CONFIG_FILE}" "[searchguard.ssl.http.pemtrustedcas_filepath]")
	OLD_PRIVATEKEY4upgrade="${OLD_CONFIG_PATH}/${PRIVATEKEY4upgrade}"
	OLD_CERTIFICATE4upgrade="${OLD_CONFIG_PATH}/${CERTIFICATE4upgrade}"
	OLD_CERTAUTH4upgrade="${OLD_CONFIG_PATH}/${CERTAUTH4upgrade}"
	if [ ! -f "${OLD_PRIVATEKEY4upgrade}" ] || [ ! -f "${OLD_CERTIFICATE4upgrade}" ] || [ ! -f "${OLD_CERTAUTH4upgrade}" ]; then
		jksused=$(get_yaml "${OLD_CONFIG_FILE}" "[searchguard.ssl.http.truststore_filepath]")
		if [ -n ${jksused} ]; then
			info_logging "Truststore is used, ${jksused} "
			jksflag="jkstrue"
		else
			error_logging "The old certificates are missing ${OLD_CERTIFICATE4upgrade}. The upgrading was aborted."
			return 1
		fi
	fi
	
		if [ -n "${SETUP_CONFIG_SRC_PATH}" ] && [ -n "${OLD_PRIVATEKEY_TMP}" ]; then
			OLD_PRIVATEKEY=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "PrivateKey")
			OLD_CERTIFICATE=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "Certificate")
			OLD_CERTAUTH=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "CertAuth")
			PRIVATEKEY=$(basename "${OLD_PRIVATEKEY}")
			CERTIFICATE=$(basename "${OLD_CERTIFICATE}")
			CERTAUTH=$(basename "${OLD_CERTAUTH}")
			info_logging "Using the certificates provided in setup.conf file."
			info_logging "OLD_PRIVATEKEY: ${OLD_PRIVATEKEY}, OLD_CERTIFICATE: ${OLD_CERTIFICATE}, OLD_CERTAUTH: ${OLD_CERTAUTH} "
			#yes | cp -f ./config/cacert.pem  "${OLD_CERTAUTH}"
            #yes | cp -f ./config/cert.pem  "${OLD_CERTIFICATE}"
			#yes | cp -f ./config/key.pem  "${OLD_PRIVATEKEY}"
			
		else
			PRIVATEKEY="${PRIVATEKEY4upgrade}"
			CERTIFICATE="${CERTIFICATE4upgrade}"
			CERTAUTH="${CERTAUTH4upgrade}"
			OLD_PRIVATEKEY="${OLD_PRIVATEKEY4upgrade}"
			OLD_CERTIFICATE="${OLD_CERTIFICATE4upgrade}"
			OLD_CERTAUTH="${OLD_CERTAUTH4upgrade}"
			info_logging "Using the previous certificates."
		fi

		CERTIFICATE1=$(get_yaml "${OLD_CONFIG_FILE}" "[searchguard.ssl.http.pemcert_filepath]")
                OLD_CERTIFICATE1="${OLD_CONFIG_PATH}/${CERTIFICATE1}"
                diff "${OLD_CERTIFICATE}" "${OLD_CERTIFICATE1}" &>/dev/null
                if [ $? -eq 0 ]; then
                        match="yes"
						info_logging "The new certificate ${OLD_CERTIFICATE} is same as the previous one ${OLD_CERTIFICATE1}"
                fi
		if [ "${jksflag}" == "jksfalse" ] && [ -f "${OLD_PRIVATEKEY}" ] && [ -f "${OLD_CERTIFICATE}" ] && [ -f "${OLD_CERTAUTH}" ]; then
			yes | cp -f "${OLD_PRIVATEKEY}" "${LOG_PATH}"
			yes | cp -f "${OLD_CERTIFICATE}" "${LOG_PATH}"
			yes | cp -f "${OLD_CERTAUTH}" "${LOG_PATH}"
		fi

		if [[ "${match}" == "yes" ]]; then
                        CERT_SUBJECT=$(get_yaml "${OLD_CONFIG_FILE}" "[searchguard.authcz.admin_dn].[0]")
                fi

	#fi

	JVM_FILE="${OLD_CONFIG_PATH}"/jvm.options
	OLD_MEMORYLIMIT=$(grep "^-Xms[0-9].*" "${JVM_FILE}" | cut -d "s" -f2)
	SERVICEFILE="/etc/init.d/${OLD_SERVICENAME}"
	OLD_CPULIMIT=$(grep "CPUQuota=" "${SERVICEFILE}" | cut -d "=" -f2)
	if [[ -z "${OLD_CPULIMIT}" ]]; then
		limitLine=$(cat ${SERVICEFILE} | grep "cpu.cfs_quota_us" | cut -d " " -f2)
		if [[ ! -z "${limitLine}" ]]; then
			cpu_cfs_period_us=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
			if [[ ! -z "${cpu_cfs_period_us}" ]]; then
				OLD_CPULIMIT=$(expr ${limitLine} \* 100 / ${cpu_cfs_period_us})
				if [[ ! -z "${OLD_CPULIMIT}" ]]; then
					OLD_CPULIMIT="${OLD_CPULIMIT}%"
				fi
			fi
		fi
	fi
	info_logging "Check username. "
	sgversion=$(ls "${OLD_INSTALL_PATH}/plugins"|grep -i search-guard)
	sgversion=${sgversion##*( )}
	SgInternalUsers="${OLD_INSTALL_PATH}/plugins/${sgversion}/sgconfig/sg_internal_users.yml"
	pluginspath="${OLD_INSTALL_PATH}/plugins/${sgversion}"
	#Start backing up the old Search Guard sg_internal_users.yml file
	back_up_user_info
	if [ $? -ne 0 ]; then
		warn_logging "Failed to back up old Search Guard sg_internal_users.yml file."
	fi
	#Start creating temporary account for validating Search Guard
	while [ 1 ];do
		tmpuser=`tr -cd '[:alnum:]' < /dev/urandom | fold -w11 | head -n1`
        tmpasswd=`tr -cd '[:alnum:]' < /dev/urandom | fold -w12 | head -n1`
		if [[ -f "${SgInternalUsers}" ]]; then
			cat "${SgInternalUsers}" | grep -w "${tmpuser}"
			if [ $? -eq 0 ]; then
				info_logging "${tmpuser} exists, create an new temporary user."
			else
				break
			fi
		else
			info_logging "${SgInternalUsers} does not exist."
			break
		fi
	done

	if [[ "${flag}" == "true"  ]]; then	
		OLD_USERNAME=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "UserName")
		OLD_PASSWORD=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "Password")
		OLD_BINDIP_TMP=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "ActualIp")
		if [ -n "${OLD_BINDIP_TMP}" ]; then
			OLD_BINDIP=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "ActualIp")
		fi
		if [[ "${ReplaceAccount}" == "true" ]]; then
			mongodb_username=${OLD_USERNAME}
			mongodb_password=${OLD_PASSWORD}
			info_logging "This is AllInTwo upgrade, the old account will be replaced with MongoDB account."
		fi
	else
		if [ -f "/etc/netbrain/install_elasticsearch.conf" ]; then
			info_logging "Configuration file /etc/netbrain/install_elasticsearch.conf already exists."
			while IFS='' read -r line || [[ -n "$line" ]]; do
				read -r key value <<<"$line"
				if [[ ! "$line" =~ ^# && "$line" ]]; then
					if [ -z "$value" ]; then
						first="${key:0:1}"
						if [[ ! "$first" == *[\[\#]* ]]; then
							info_logging "Value for $key is not specified."
						fi
					fi
					if [[ "$key" = "User" ]]; then
						OLD_USERNAME="$value"
					elif [[ "$key" == "Password" ]]; then
						OLD_PASSWORD="$value"
					fi
				fi
			done <"/etc/netbrain/install_elasticsearch.conf"
		fi
	fi


		verify_account
                if [[ $? -ne 0 ]]; then
						if [[ "${flag}" == "true" ]]; then 
							get_userinfo
							verify_account
							if [[ $? -ne 0 ]]; then						
								OLD_USERNAME=""
								OLD_PASSWORD=""
								info_logging "The usernames and passwords from both setup.conf and install_elasticsearch.conf file have no access to ES."
							fi
						else
							OLD_USERNAME=""
							OLD_PASSWORD=""
							info_logging "The usernames and passwords from both setup.conf and install_elasticsearch.conf file have no access to ES."
						
						fi
						
				else 
				
					if [[ -f "${SgInternalUsers}" ]]; then
						cp -p "${SgInternalUsers}"  "${LOG_PATH}/"
						cat "${SgInternalUsers}" >> ${INSTALL_LOG} 2>&1
						info_logging "Succeeded in backing up Search Guard sg_internal_users.yml file."
					else
						error_logging "${SgInternalUsers} does not exist, please check if Search Guard had been installed."
						return 2
					fi
				fi


		while [[ -z "${OLD_USERNAME}" ]] && [[ ${jksflag} == "jksfalse" ]]; do
		#	read -p "Please enter the Elasticsearch username: " OLD_USERNAME
			OLD_USERNAME=$tmpuser
            		OLD_PASSWORD=$tmpasswd
            		add_user
			break
		done

		#while [ -z "${OLD_PASSWORD}" ]; do
		#	read -sp "Please enter the Elasticsearch password: " OLD_PASSWORD
		#	echo -e "\r"
		#done

		export s1=$(echo "${http_proxy}")
		export s2=$(echo "${https_proxy}")
		export http_proxy=""
		export https_proxy=""

		while true; do
		
			if [[ "${AllInTwo}" == "true" ]] && [[ "${jksflag}" == "jkstrue" ]]; then
				info_logging "It is AllInTwo upgrade and the previous ES uses the truststore, skipping verification..."
				testversion=5
				break
			fi

			if [ "${OLD_USESSL4upgrade}" != "true" ]; then
				testversion=$(curl --tlsv1.2 -s -XGET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" http://127.0.0.1:"${OLD_PORT}" | grep "number" | cut -d ":" -f2 | cut -d "\"" -f2)
			else
				testversion=$(curl --tlsv1.2 -k -s -XGET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" https://127.0.0.1:"${OLD_PORT}" | grep "number" | cut -d ":" -f2 | cut -d "\"" -f2)
			fi
			if [ -z "${testversion}" ]; then
				info_logging "Failed to login to Elasticsearch."

				read -p "Please enter the Elasticsearch username: " OLD_USERNAME
				while [ -z "${OLD_USERNAME}" ]; do
					read -p "Please enter the Elasticsearch username: " OLD_USERNAME
				done
				read -sp "Please enter the Elasticsearch password: " OLD_PASSWORD
				while [ -z "${OLD_PASSWORD}" ]; do
					read -sp "Please enter the Elasticsearch password: " OLD_PASSWORD
					echo -e "\r"
				done
				echo -e "\r"
			else
				info_logging "Successfully connected to Elasticsearch."
				break
			fi
		done

		testversion=$(echo "$testversion" | cut -d "." -f1)
		if [ "$testversion" -eq 6 ]; then
			testversion=upgrading
		else
			testversion=remove
		fi
	

	if nb_is_1010_from_releaseinfo "${FIX_RELEASE_INFO}"; then
	#if [[ "$oldversion" == "10.0.10" ]]; then
		warn_logging "The latest version of ${COMPONENT_NAME} has been installed."
		return 2
	fi

	info_logging "User value is : ${OLD_USERNAME}"
	info_logging "Password value is : ******"
	info_logging "User value is : ${mongodb_username}"
	info_logging "Password value is : ******"	
	info_logging "DataPath value is : ${OLD_DATAPATH}"
	info_logging "LogPath value : ${OLD_LOGPATH}"
	info_logging "CPULimit value is : ${OLD_CPULIMIT}"
	info_logging "MemoryLimit value is : ${OLD_MEMORYLIMIT}"
	info_logging "UseSSL value is : ${usessl}"
	#info_logging "PrivateKey value is : ${ES_PRIVATEKEY}"
	#info_logging "Certificate value is : ${ES_CERTIFICATE}"
	#info_logging "CertAuth value : ${ES_CERTAUTH}"
	info_logging "ClusterName value is : ${OLD_CLUSTERNAME}"
	info_logging "NodeName value is : ${OLD_NODENAME}"
	info_logging "ClusterMembers value is : ${OLD_CLUSTERMEMBERS}"
	info_logging "Ciphers value is : ${OLD_CIPHERS}"
	info_logging "MasterOnlyNode value is : ${OLD_MASTERONLYNODE}"
	#info_logging "estestversion value is : ${testversion}"

	export http_proxy="${s1}"
	export https_proxy="${s2}"
	info_logging "Getting the previous installation parameters $(green "SUCCEEDED")."
	
	return 0
}

conf_setting() {
	#info_logging "Starting to configuration parameters updating..."
	if [ "${ReplaceAccount}" == "true" ] && [ "${flag}" == "true" ] && [ -n "${mongodb_username}" ]; then
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "UserName" "${mongodb_username}" >&/dev/null 2>&1
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "Password" "${mongodb_password}" >&/dev/null 2>&1
	else
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "UserName" "${OLD_USERNAME}" >&/dev/null 2>&1
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "Password" "${OLD_PASSWORD}" >&/dev/null 2>&1
	fi
	set_ini "$SCRIPT_PATH/config/setup.conf" "" "DataPath" "${OLD_DATAPATH}" >&/dev/null 2>&1
	set_ini "$SCRIPT_PATH/config/setup.conf" "" "LogPath" "${OLD_LOGPATH}" >&/dev/null 2>&1
	set_ini "$SCRIPT_PATH/config/setup.conf" "" "BindIp" "${OLD_BINDIP}" >&/dev/null 2>&1
	set_ini "$SCRIPT_PATH/config/setup.conf" "" "Port" "${OLD_PORT}" >&/dev/null 2>&1
	set_ini "$SCRIPT_PATH/config/setup.conf" "" "MasterOnlyNode" "${OLD_MASTERONLYNODE}" >&/dev/null 2>&1
	if [ -n "${OLD_CPULIMIT}" ]; then
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "CPULimit" "${OLD_CPULIMIT}" >&/dev/null 2>&1
	fi
	
	if [[ "${OLD_MEMORYLIMIT}" == *"%"* ]]; then
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "MemoryLimit" "${OLD_MEMORYLIMIT}" >/dev/null 2>&1
	fi

	if [[ "${usessl}" = "yes" ]]; then
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "UseSSL" "yes" >&/dev/null 2>&1
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "PrivateKey" "${LOG_PATH}/${PRIVATEKEY}" >&/dev/null 2>&1
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "Certificate" "${LOG_PATH}/${CERTIFICATE}" >&/dev/null 2>&1
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "CertAuth" "${LOG_PATH}/${CERTAUTH}" >&/dev/null 2>&1
	else
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "UseSSL" "no" >&/dev/null 2>&1
                set_ini "$SCRIPT_PATH/config/setup.conf" "" "PrivateKey" "${LOG_PATH}/${PRIVATEKEY}" >&/dev/null 2>&1
                set_ini "$SCRIPT_PATH/config/setup.conf" "" "Certificate" "${LOG_PATH}/${CERTIFICATE}" >&/dev/null 2>&1
                set_ini "$SCRIPT_PATH/config/setup.conf" "" "CertAuth" "${LOG_PATH}/${CERTAUTH}" >&/dev/null 2>&1
	fi

	set_ini "$SCRIPT_PATH/config/setup.conf" "" "ClusterName" "${OLD_CLUSTERNAME}" >&/dev/null 2>&1
	set_ini "$SCRIPT_PATH/config/setup.conf" "" "NodeName" "${OLD_NODENAME}" >&/dev/null 2>&1

	if [[ "${OLD_CLUSTERMEMBERS}" != "null" ]]; then
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "SingleNode" "no" >&/dev/null 2>&1
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "ClusterMembers" "${OLD_CLUSTERMEMBERS}" >&/dev/null 2>&1
	fi
	
	if [[ "${OLD_CIPHERS}" != "null" ]]; then
		set_ini "$SCRIPT_PATH/config/setup.conf" "" "Ciphers" "${OLD_CIPHERS}" >& /dev/null 2>&1
	fi

	#info_logging "Configuration parameters updating $(green "SUCCEEDED")."
	
	return 0
}

uninstall_old_version() {
	#"${SCRIPT_PATH}"/others/uninstall.sh "${testversion}"

	if [[ "${OLD_PORT}" == "null" ]]; then
		OLD_PORT="9200"
	fi

	crontab -l | sed "/service $OLD_SERVICENAME /d" | crontab

	#testps=$(pgrep -f "elasticsearch")
	#if [ -n "$testps" ]; then
	#kill -9 "$testps"
	#fi
	systemctl stop "$OLD_SERVICENAME"
	sleep 10s
	sed -i '/vm.max_map_count=262144/d' /etc/sysctl.conf
	sed -i '/*          hard    nproc    64000/d' /etc/security/limits.conf
	sed -i '/*          soft    nproc    64000/d' /etc/security/limits.conf
	sed -i '/*          hard    nofile   64000/d' /etc/security/limits.conf
	sed -i '/*          soft    nofile   64000/d' /etc/security/limits.conf
	sed -i '/soft nproc 32768/d' /etc/security/limits.conf
	sed -i '/hard nproc 65536/d' /etc/security/limits.conf
	sed -i '/soft memlock unlimited/d' /etc/security/limits.conf
	sed -i '/hard memlock unlimited/d' /etc/security/limits.conf
	sed -i '/  -  nofile    65536/d' /etc/security/limits.conf
	sysctl -p

	chkconfig --del "$OLD_SERVICENAME"

	if rpm -qa "${RPM_NAME}" | grep -q "${RPM_NAME}" >&/dev/null; then
		rpm -e "${RPM_NAME}" || verify_operation
	fi

	if [ -d "${OLD_INSTALL_PATH}" ]; then
		FILE_LIST=("${SERVICEFILE}" "/etc/netbrain/install_elasticsearch.conf" "/etc/netbrain/elasticsearch_installed" "/etc/netbrain/install_esmaster.conf" "${OLD_INSTALL_PATH}/fix_releaseinfo.json" "${OLD_INSTALL_PATH}/LICENSE.txt" "${OLD_INSTALL_PATH}/NOTICE.txt" "${OLD_INSTALL_PATH}/README.textile" "$OLD_LOGPATH/elasticsearch_install.log")
	fi

	for p in ${FILE_LIST[*]}; do
		if [ -f "${p}" ]; then
			rm -rf "${p}"
		fi
	done

	if [ -f "${OLD_INSTALL_PATH}/logs/gc.log" ]; then
		rm -rf "${OLD_INSTALL_PATH}"/logs/gc*
	fi

	if [ -f "$OLD_LOGPATH/$OLD_CLUSTERNAME.log" ]; then
		mv "$OLD_LOGPATH/$OLD_CLUSTERNAME.log" "${OLD_LOGPATH}"/"${OLD_CLUSTERNAME}"_save.log
	fi

	if [ -d "${OLD_INSTALL_PATH}" ]; then
		DIR_LIST=("${OLD_INSTALL_PATH}/bin" "${OLD_INSTALL_PATH}/config" "${OLD_INSTALL_PATH}/lib" "${OLD_INSTALL_PATH}/modules" "${OLD_INSTALL_PATH}/pid" "${OLD_INSTALL_PATH}/plugins" "${OLD_INSTALL_PATH}/temp")
	fi

	for p in ${DIR_LIST[*]}; do
		if [ -d "${p}" ]; then
			rm -rf "${p}"
		fi
	done

	if [[ -d "${OLD_INSTALL_PATH}/logs" ]]; then
		testdir=$(find "${OLD_INSTALL_PATH}"/logs -type f | wc -l)
		if [ "${testdir}" -eq 0 ]; then
			rm -rf "${OLD_INSTALL_PATH}/logs"
		fi
	fi

	if [[ -d "/etc/netbrain" ]]; then
		testdir=$(find "/etc/netbrain" -type f | wc -l)
		if [ "${testdir}" -eq 0 ]; then
			rm -rf "/etc/netbrain"
		fi
	fi

	if [[ -d "${OLD_INSTALL_PATH}" ]]; then
		testdir=$(find "${OLD_INSTALL_PATH}" -type f | wc -l)
		if [ "${testdir}" -eq 0 ]; then
			rm -rf "${OLD_INSTALL_PATH}"
		fi
	fi

	remove_port_from_firewall "${OLD_PORT}"
	remove_port_from_firewall "9300"

	if [[ "${testversion}" == "remove" ]]; then
		local PATHS=("${OLD_CONFIG_PATH}" "${OLD_LOGPATH}" "${OLD_DATAPATH}" "${OLD_INSTALL_PATH}")
		for p in ${PATHS[*]}; do
			rm -rf "${p}"
		done
	fi

	if [ ! -f "${SERVICEFILE}" ]; then
		info_logging "Uninstalling Elasticsearch $(green "SUCCEEDED")."
	fi
	
	return 0
}

install_new_version() {
	if [ -n "${1}" ]; then
		LOGSET="${1}"
	else
		LOGSET="upgrading"
	fi

	# Only the ES7.01b uses keystore & truststore, therefore, the value of  
	# 'match' should not be 'yes' when upgrading ES7.01b.
	if [[ "${match}" == "yes" ]]; then
		"${SCRIPT_PATH}"/install.sh "${LOGSET}" "${CERT_SUBJECT}"
	else
		"${SCRIPT_PATH}"/install.sh "${LOGSET}" "${jksflag}"
	fi
                
	info_logging "Install log location: ${INSTALL_LOG}"
	testlog=$(grep "Successfully installed Elasticsearch. Service is running." "${INSTALL_LOG}")

	if [ -z "$testlog" ]; then
		error_logging "Failed to install new Elasticsearch. The upgrading was aborted."
		return 1
	else
		#info_logging "Installing new Elasticsearch $(green "SUCCEEDED")."
		FILE_LIST=("${UPGRADE_TEMP}" "${LOG_PATH}/${PRIVATEKEY}" "${LOG_PATH}/${CERTIFICATE}" "${LOG_PATH}/${CERTAUTH}")
		for p in ${FILE_LIST[*]}; do
			if [ -f "${p}" ] && [ ${AllInTwo} == "false" ]; then
				rm -rf "${p}"
				info_logging "${p} has been deleted."
			fi
		done
	fi
	
	return 0
}

delete_old_index() {
	if [ "$usessl" == "no" ]; then
		OLD_INDEX=$(curl --tlsv1.2 -s -XGET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" http://127.0.0.1:"${OLD_PORT}"/_cat/indices?h=index)
	else
		OLD_INDEX=$(curl --tlsv1.2 -k -s -XGET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" https://127.0.0.1:"${OLD_PORT}"/_cat/indices?h=index)
	fi

	#DEL_LIST=("checkpoint" "etl_settings" "_devicegroup_" "_path_" "_site_" "_device_" "_dashboard_" "_map_" "_interface_")
	#DEL_LIST=("checkpoint" "etl_checkpoint" "etl_settings" "_devicegroup_" "_path_" "_site_" "_device_" "_dashboard_" "_map_" "_interface_" "_alerteventstatistics_" "_globalendpoint_" "_automationasset-dtguidebook_" "_incident_" "_networktree_" "_ni_" "_oneiptable_" "_stage")

	#for p in ${OLD_INDEX[*]}; do
	#	for q in ${DEL_LIST[*]}; do
	#		if [[ "${p}" =~ "${q}" ]] && [[ ! "${p}" =~ "monitor" ]]; then
	#			if [ "$usessl" == "no" ]; then
	#				curl --tlsv1.2 -s -XGET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" -XDELETE "http://127.0.0.1:${OLD_PORT}/${p}" >/dev/null 2>&1
	#			else
	#				curl --tlsv1.2 -k -s -XGET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" -XDELETE "https://127.0.0.1:${OLD_PORT}/${p}" >/dev/null 2>&1
	#			fi
	#		fi
	#	done
	#done
	
	return 0
}

get_userinfo() {
	
	if [ -f "/etc/netbrain/install_elasticsearch.conf" ]; then
			info_logging "Configuration file /etc/netbrain/install_elasticsearch.conf already exists."
			while IFS='' read -r line || [[ -n "$line" ]]; do
				read -r key value <<<"$line"
				if [[ ! "$line" =~ ^# && "$line" ]]; then
					if [ -z "$value" ]; then
						first="${key:0:1}"
						if [[ ! "$first" == *[\[\#]* ]]; then
							info_logging "Value for $key is not specified."
						fi
					fi
					if [[ "$key" = "User" ]]; then
						OLD_USERNAME="$value"
					elif [[ "$key" == "Password" ]]; then
						OLD_PASSWORD="$value"
					fi
				fi
			done <"/etc/netbrain/install_elasticsearch.conf"
	fi

	return 0

}

verify_account() {
	if [ "${OLD_USESSL4upgrade}" != "true" ]; then
				testversion=$(curl --tlsv1.2 -s -XGET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" http://127.0.0.1:"${OLD_PORT}" | grep "number" | cut -d ":" -f2 | cut -d "\"" -f2)
	else
				testversion=$(curl --tlsv1.2 -k -s -XGET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" https://127.0.0.1:"${OLD_PORT}" | grep "number" | cut -d ":" -f2 | cut -d "\"" -f2)
	fi
	if [ -z "${testversion}" ]; then
				info_logging "Failed to login to Elasticsearch."
				return 1
	fi
	return 0

}

back_up_user_info() {
	info_logging "Starting to back up Search Guard sg_internal_users.yml file."
	if [[ -f "${SgInternalUsers}" ]]; then
		cp -p "${SgInternalUsers}"  "${LOG_PATH}/"
		cat "${SgInternalUsers}" >> ${INSTALL_LOG} 2>&1
		info_logging "Succeeded in backing up Search Guard sg_internal_users.yml file."		
	else
		error_logging "${SgInternalUsers} does not exist, please check if Search Guard had been installed."
		return 2
	fi
	return 0
}

add_user(){
	local tmpnum=0
	local errnum=0
	
	if [[ "${usessl}" == "no" ]]; then
                curl -XPUT -s --cert "${OLD_CERTIFICATE4upgrade}" --key "${OLD_PRIVATEKEY4upgrade}" -H "Content-Type: application/json" http://127.0.0.1:"${OLD_PORT}"/_all/_settings -d '{"index.blocks.read_only_allow_delete": null}'
                if [[ $? -ne 0 ]]; then
                error_logging "Failed to reseting read_only_allow_delete."
                return 1
                fi
        else
                curl -XPUT -k -s --cert "${OLD_CERTIFICATE4upgrade}" --key "${OLD_PRIVATEKEY4upgrade}" -H "Content-Type: application/json" https://127.0.0.1:"${OLD_PORT}"/_all/_settings -d '{"index.blocks.read_only_allow_delete": null}'
                if [[ $? -ne 0 ]]; then
                error_logging "Failed to reseting read_only_allow_delete."
                return 1
                fi
        fi

    
        #chown -R $systemuser:$systemgroup $INSTALL_PATH

	"${pluginspath}"/tools/hash.sh -env "${OLD_USERNAME}" -p "${OLD_PASSWORD}" >"${LOG_PATH}"/hash
        sed -i '/WARNING/d' "${LOG_PATH}"/hash
        Hash=$(sed -n '1p' "$LOG_PATH"/hash)
       	{
       	 	echo "$OLD_USERNAME:"
       	 	echo "  hash: $Hash"
       	 	echo "  roles:"
       	 	echo "    - admin"
       	} >>"$SgInternalUsers"
	
        rm -f "$LOG_PATH"/hash
		
	for ((i = 0; i < 10; )); do
        tmpnum=$(cat "${INSTALL_LOG}"|grep "ERR"|grep -v -w "Seems you use a node certificate which is also an admin certificate"|wc -l)
        "${pluginspath}"/tools/sgadmin.sh -cd "${pluginspath}"/sgconfig -cacert "${OLD_CERTAUTH4upgrade}" -cert "${OLD_CERTIFICATE4upgrade}" -key "${OLD_PRIVATEKEY4upgrade}" -icl -nhnv >>"${INSTALL_LOG}"
        errnum=$(cat "${INSTALL_LOG}"|grep "ERR"|grep -v -w "Seems you use a node certificate which is also an admin certificate"|wc -l)
        if [[ ${errnum} -eq ${tmpnum} ]]; then
            break
        fi
		((i++))
    done
    if [[ $i -eq 10 ]]; then
        warn_logging "Failed to initialize Search Guard."
        return 1
    fi

	return 0
}


del_temp_user_restore_old_user(){
	local tmpnum=0
	local errnum=0
	
	if [[ -f "${LOG_PATH}/sg_internal_users.yml" ]]; then
		mv "${LOG_PATH}/sg_internal_users.yml" "${INSTALL_PATH}/plugins/search-guard-6/sgconfig/"
		chown root:root "${INSTALL_PATH}/plugins/search-guard-6/sgconfig/sg_internal_users.yml"
		chmod 755 "${INSTALL_PATH}/plugins/search-guard-6/sgconfig/sg_internal_users.yml"
	else
		warn_logging "${LOG_PATH}/sg_internal_users is missing, please take a look."
		return 1
	fi
	info_logging "Deleting ${tmpuser} account from Search Guard..."
	pluginspath="${INSTALL_PATH}/plugins/search-guard-6"
	
	NEW_CONFIG_FILE="/etc/elasticsearch/elasticsearch.yml"
	NEW_CERTAUTH=$(get_yaml "${NEW_CONFIG_FILE}" "[searchguard.ssl.transport.pemtrustedcas_filepath]")
	NEW_CERTIFICATE=$(get_yaml "${NEW_CONFIG_FILE}" "[searchguard.ssl.transport.pemcert_filepath]")
	NEW_PRIVATEKEY=$(get_yaml "${NEW_CONFIG_FILE}" "[searchguard.ssl.transport.pemkey_filepath]")
	NEW_CERTAUTH="/etc/elasticsearch/${NEW_CERTAUTH}"
	NEW_CERTIFICATE="/etc/elasticsearch/${NEW_CERTIFICATE}"
	NEW_PRIVATEKEY="/etc/elasticsearch/${NEW_PRIVATEKEY}"

    for ((i = 0; i < 10; )); do
        tmpnum=$(cat "${INSTALL_LOG}"|grep "ERR"|grep -v -w "Seems you use a node certificate which is also an admin certificate"|wc -l)
        "${pluginspath}"/tools/sgadmin.sh -cd "${pluginspath}"/sgconfig -cacert "${NEW_CERTAUTH}" -cert "${NEW_CERTIFICATE}" -key "${NEW_PRIVATEKEY}" -icl -nhnv >>"${INSTALL_LOG}"
        errnum=$(cat "${INSTALL_LOG}"|grep "ERR"|grep -v -w "Seems you use a node certificate which is also an admin certificate"|wc -l)
        if [[ ${errnum} -eq ${tmpnum} ]]; then
            break
        fi
		((i++))
    done
    if [[ $i -eq 10 ]]; then
        warn_logging "Failed to initialize Search Guard."
        return 1
    fi
		
	return 0
}

collect_es_info() {
        create_log_file "${UPGRADE_TEMP}"
        if [ $? -ne 0 ]; then
                error_logging "$(get_last_error) The upgrading was aborted."
                return 1
        else
                info_logging "Creating upgrade_tmp file $(green "SUCCEEDED")"
        fi
        pgrep -af "elasticsearch" >"${UPGRADE_TEMP}"
        sed -i "s@ @\n@g" "${UPGRADE_TEMP}"
		
		return 0
}



manage_shard_allocation() {
	arg1=${1}
	if [[ "${arg1}" == "disable" ]]; then
		if [[ "${ES_USESSL}" == "false" ]]; then
			curl --tlsv1.2 -s -X PUT --user "${OLD_USERNAME}":"${OLD_PASSWORD}" "http://127.0.0.1:${OLD_PORT}/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
                        {
                        "persistent": {
                                "cluster.routing.allocation.enable": "primaries"
                                }
                        }
                        '
			curl --tlsv1.2 -s -X POST --user "${OLD_USERNAME}":"${OLD_PASSWORD}" "http://127.0.0.1:9200/_flush/synced?pretty"
		else
			curl --tlsv1.2 -k -s -X PUT --user "${OLD_USERNAME}":"${OLD_PASSWORD}" "https://127.0.0.1:${OLD_PORT}/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
                        {
                        "persistent": {
                                "cluster.routing.allocation.enable": "primaries"
                                }
                        }
                        '
			curl --tlsv1.2 -k -s -X POST --user "${OLD_USERNAME}":"${OLD_PASSWORD}" "http://127.0.0.1:9200/_flush/synced?pretty"
		fi
	fi

	if [[ "${arg1}" == "enable" ]]; then
		if [[ "${ES_USESSL}" == "false" ]]; then
			curl --tlsv1.2 -s -X PUT --user "${OLD_USERNAME}":"${OLD_PASSWORD}" "http://127.0.0.1:${OLD_PORT}/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
                        {
                        "persistent": {
                                "cluster.routing.allocation.enable": null
                                }
                        }
                        '
		else
			curl --tlsv1.2 -k -s -X PUT --user "${OLD_USERNAME}":"${OLD_PASSWORD}" "https://127.0.0.1:${OLD_PORT}/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
                        {
                        "persistent": {
                                "cluster.routing.allocation.enable": null
                                }
                        }
                        '
		fi
	fi
	
	return 0
}

check_health() {
	local i=1
	while true; do
		if [ "$usessl" == "no" ]; then
			line=`curl --tlsv1.2 -s -X GET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" -X GET "http://127.0.0.1:${OLD_PORT}/_cat/health?v"|grep -v timestamp`
		else
			line=`curl --tlsv1.2 -k -s -X GET --user "${OLD_USERNAME}":"${OLD_PASSWORD}" -X GET "https://127.0.0.1:${OLD_PORT}/_cat/health?v"|grep -v timestamp`
		fi

		clusterStatus=`echo $line|awk '{print $4}'`
		relo=`echo $line|awk '{print $9}'`
		init=`echo $line|awk '{print $10}'` 

		if [ $init -eq 0 ] || [ $relo -eq 0 ]; then
			info_logging "init: ${init} , relo: ${relo}, clusterStatus: ${clusterStatus}."
		fi

		if [[ ${clusterStatus} == "green" ]]; then
			break
		fi

		if [ ${clusterStatus} == "yellow" ] && [ $init -eq 0 ] && [ $relo -eq 0 ]; then
                        break
                fi

		if [[ $i -gt 20 ]]; then
			info_logging "cluster is not in correct status, please check. status: ${clusterStatus}, init: ${init}, relo: ${relo}."
			clusterStatus="error"
			break
		fi
		info_logging "It is the NO.$i to check if cluster has came back to normal, please wait..."
		sleep 30
		((i++))

	done
	
	return 0

}

postprocessing() {
	#info_logging "n/a" >/dev/null 2>&1
	nb_backup_uninstall_files "${SCRIPT_PATH}" "${UNINSTALL_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The upgrading was aborted."
		return 1
	fi

	if [ -e "${INSTALL_PATH}/fix_releaseinfo.json" ]; then
		rm -rf "${INSTALL_PATH}/fix_releaseinfo.json"
	fi
	yes | cp -arf fix_releaseinfo.json "${INSTALL_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "Failed to save fix_releaseinfo.json. The upgrading was aborted."
		return 1
	fi
	chmod 664 "${INSTALL_PATH}"/fix_releaseinfo.json

	nb_backup_release_info_file "${SCRIPT_PATH}" "${UNINSTALL_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The upgrading was aborted."
		return 1
	fi

	nb_restore_setup_conf "${SCRIPT_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The upgrading was aborted."
		return 1
	fi

	#systemctl status "${SERVICE_NAME}" 2>/dev/null
	teststatus=$(systemctl status ${SERVICE_NAME} --no-pager| grep running)
	if [ -n "$teststatus" ]; then
		info_logging "Successfully upgraded ${COMPONENT_NAME}. Service is running."
	else
		info_logging "Successfully upgraded ${COMPONENT_NAME}, but the service cannot be started up."
	fi

	info_logging "Backing up uninstall.sh $(green "SUCCEEDED")."
	info_logging "Upgrading ${COMPONENT_NAME} $(green "SUCCEEDED")."
	
	return 0
}

clean() {
	remove_color_in_log
	return 0
}

main() {	
	info_logging "Starting to upgrade ${COMPONENT_NAME} ..."
	OLD_INSTALL_PATH=$(get_ini "${UPGRADE_TEMP}" "" "-Des.path.home")
	info_logging "The old install path is $OLD_INSTALL_PATH ."
	if [ -z "${OLD_INSTALL_PATH}" ]; then
		grep "Starts and stops a single elasticsearch instance on this system" /etc/init.d/*
		if [ $? -ne 0 ] && [ ! -f /usr/lib/systemd/system/elasticsearch.service ]; then
			# Fresh install is required.
			info_logging "${COMPONENT_NAME} was not installed. Fresh installation is required. "
			return 1
		else
			info_logging "The service of ${COMPONENT_NAME} is not running. Please start the service first."
			return 1
		fi
	
	fi
	
	if nb_is_1010_from_releaseinfo "${FIX_RELEASE_INFO}" ; then
		info_logging "The latest version of ${COMPONENT_NAME} has been installed."
		return 2		
	else
		#service monitor exists checking
		if ! checking_service_monitor "${SCRIPT_PATH}" "${COMPONENT_NAME}" "${MONITOR_VERSION}" "upgrading"; then
			error_logging "$(get_last_error) The upgrading was aborted."
			return 1
		fi
	
		get_old_setup_parameters "${2}"
		if [ $? -ne 0 ]; then
			return 1
		fi
		check_certs
		if [ $? -ne 0 ]; then
			return 1
		fi		
		conf_setting
		if [ $? -ne 0 ]; then
			return 1
		fi
		if [[ "${OLD_CLUSTERMEMBERS}" != "null" ]] && [[ "${jksflag}" == "jksfalse" ]]; then
			manage_shard_allocation disable
		fi
		uninstall_old_version
		if [ $? -ne 0 ]; then
			return 1
		fi
		install_new_version "${1}"
		if [ $? -ne 0 ]; then
			return 1
		fi

		set_java_home
		if [ $? -ne 0 ]; then
                        return 1
                fi


		if [[ "${OLD_CLUSTERMEMBERS}" != "null" ]] && [[ "${jksflag}" == "jksfalse" ]]; then
			manage_shard_allocation enable
		fi
		
		if [[ "${jksflag}" == "jkstrue" ]]; then
			info_logging "Skipping deleting old indicies when it is AllInTwo upgrade and truststore is used in proveious version."
		#else
		#	delete_old_index
		fi
		
		set_user_creation_immutable
		#check_health
		if [[ "${OLD_CLUSTERMEMBERS}" != "null" ]] && [[ "${jksflag}" == "jksfalse" ]]; then
			check_health
			if [[ "$clusterStatus" == "green" ]]; then
				info_logging "Cluster status is $(green "green")."
			fi
			if [[ "$clusterStatus" == "error" ]]; then
				error_logging "Cluster status is ${clusterStatus}."
				del_temp_user_restore_old_user
				if [ $? -ne 0 ]; then
					warn_logging "Failed to restore the previous account information."
					#return 1
				fi
				return 1
			fi
		fi

		if [[ "${jksflag}" == "jkstrue" ]]; then
			info_logging "Do not use the previous account when truststore is used in previous version."
		else 
			del_temp_user_restore_old_user
			if [ $? -ne 0 ]; then
					warn_logging "Failed to restore the previous account information."
					#return 1
			fi
		fi

		
	fi
	info_logging "Successfully upgraded ${COMPONENT_NAME}."
	return 0
}

if [[ ${1:0:5} = "comp_" ]]; then
	"$@"
else
	setupfile=""
	logfile=""
	looptag=true
	if [[ -n "${1}" ]] && [[ "${1}" == *"setup.conf"* ]]; then
		setupfile="${1}"
	fi
	
	if [[ -n "${1}" ]] && [[ "${1}" == *"upgrade.log"* ]]; then
		logfile="${1}"
	fi
	
	if [[ -n "${2}" ]] && [[ "${2}" == *"setup.conf"* ]]; then
		setupfile="${2}"
	fi
	
	while ${looptag}; do
		init_variable "${logfile}"
		if [ $? -ne 0 ]; then
			break
		fi
		preprocessing
		if [ $? -ne 0 ]; then
			break
		fi
		main "${logfile}" "${setupfile}"
		if [ $? -ne 0 ]; then
			break
		fi
		postprocessing
		if [ $? -ne 0 ]; then
			break
		fi
		break
	done
	clean
fi
