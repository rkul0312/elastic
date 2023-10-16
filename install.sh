#!/bin/bash
# IEVersion: 11.1.0
# shellcheck source="$SCRIPT_PATH/include/source.sh"
# shellcheck disable=SC2104,SC2155,SC2162,SC2181,SC1091,SC2154

export IS_UPGRADE="${1}"
export IS_SUBJECT="${2}"

init_variable() {
	SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	cd "$SCRIPT_PATH" || return 1

	#looptag=true
	upgradeflag="false"
	
	umask 022

	source "${SCRIPT_PATH}/include/source.sh"
	PRODUCT_VERSION="11.0"
	SOFTWARE_VERSION="11.0"
	MONITOR_VERSION="11.1"

	# Variables required
	COMPONENT_NAME="Elasticsearch"
	RPM_NAME="elasticsearch"
	BUSINESS_RPM_NAME="elasticsearch"
	SERVICE_NAME="elasticsearch"

	# Java
	JAVA_BIN="/usr/share/elasticsearch/jdk/bin"

	# The following variables are optional.
	VERSION="8.5.3"
	RPM_PACKAGE_NAME="${RPM_NAME}-${VERSION}-x86_64.rpm"
	INSTALL_PATH="/usr/share/elasticsearch"
	FOLDER_NAME="elasticsearch"
	CONFIG_PATH="/etc/elasticsearch"
	PID_PATH="/var/run/elasticsearch"
	pluginspath="$INSTALL_PATH/plugins/search-guard-flx"
	LOG_PATH="/var/log/netbrain/installationlog/elasticsearch"
	UNINSTALL_PATH="$(nb_uninstall_path)/${FOLDER_NAME}"
	UNINSTALL_NAME="uninstall.sh"
	FIX_RELEASE_INFO="/usr/share/${FOLDER_NAME}/fix_releaseinfo.json"

	if [[ -n "${IS_UPGRADE}" ]] && [[ "${IS_UPGRADE}" != comp_* ]]; then
		if [[ "${IS_UPGRADE}" == "upgrading" ]]; then
			INSTALL_LOG="$(nb_comp_upgrade_log_filepath $FOLDER_NAME)"	
			upgradeflag="true"
		else
			INSTALL_LOG="${IS_UPGRADE}"
			LOG_PATH=$(dirname "${INSTALL_LOG}")
		fi
	else
		if [ -n "${1}" ]; then
			INSTALL_LOG="${1}"
			LOG_PATH=$(dirname "${INSTALL_LOG}")
		else
			INSTALL_LOG="$(nb_comp_install_log_filepath $FOLDER_NAME)"
		fi
		#PROCESS="installation"
	fi
	
	#Converting IS_UPGRADE to lower case
	IS_UPGRADE="$(echo ${IS_UPGRADE} | tr '[A-Z]' '[a-z]')"
	if [[ "${IS_UPGRADE}" =~ "upgrade" ]] && [[ "${IS_UPGRADE}" =~ "log" ]]; then
		upgradeflag="true"
	fi
	
	return 0
}

preprocessing() {
	init_variable "${1}"
	
	if [[ "${upgradeflag}" == "false" ]]; then
		checking_root
		if [ $? -ne 0 ]; then
			error "$(get_last_error) The installation aborted."
			return 1
		fi
	
		checking_date
		if [ $? -ne 0 ]; then
			error "$(get_last_error) The installation aborted."
			return 1
		fi
	
		#os checking
		checking_os
		if [ $? -ne 0 ]; then
			#cat /proc/version |grep '.el8'
			#if [ $? -ne 0 ]; then
			error "$(get_last_error) The installation aborted."
			return 1
			#fi
		fi
	fi
	
	#minimum cpu/mem checking
	checking_required_cpu 4
	if [ $? -ne 0 ]; then
		error "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_required_mem 4096
	if [ $? -ne 0 ]; then
		error "$(get_last_error) The installation aborted."
		return 1
	fi
	
	
	if [ -f "${INSTALL_LOG}" ] && [ "${upgradeflag}" == "true" ]; then
		info_logging "ES is in the peroid of upgrade, not archive the existing upgrade.log file."
	else
		create_log_file "${INSTALL_LOG}"
		if [ $? -ne 0 ]; then
			error "$(get_last_error) The installation aborted."
			return 1
		else
			info_logging "Creating installation log file $(green "SUCCEEDED")"
		fi
	fi
	
	
	#collect os log
	collecting_system_info

	info_logging "Component Name: ${COMPONENT_NAME}"
	info_logging "RPM name: ${RPM_NAME}"
	info_logging "Service name: ${SERVICE_NAME}"
	info_logging "Installation path: ${INSTALL_PATH}"
	info_logging "Config path: ${CONFIG_PATH}"

	info_logging "Preprocessing $(green "SUCCEEDED")."
	
	return 0
}

system_checking() {
	info_logging "Starting to perform system checking..."

	#if [[ -z "${IS_UPGRADE}" ]]; then
	if [[ "${upgradeflag}" == "false" ]]; then	

		#rpm/service exists checking
		checking_rpm_exists "${RPM_NAME}" "${COMPONENT_NAME}"
		if [ $? -ne 0 ]; then
			error_logging "$(get_last_error) The installation aborted."
			return 1
		fi
		checking_rpm_exists "${BUSINESS_RPM_NAME}" "${COMPONENT_NAME}"
		if [ $? -ne 0 ]; then
			error_logging "$(get_last_error) The installation aborted."
			return 1
		fi
		checking_systemd_exists "${SERVICE_NAME}" "${COMPONENT_NAME}"
		if [ $? -ne 0 ]; then
			error_logging "$(get_last_error) The installation aborted."
			return 1
		fi
		grep "Starts and stops a single elasticsearch instance on this system" /etc/init.d/* 2>&1 >/dev/null
		if [ $? -eq 0 ]; then
			error_logging "Elasticsearch has already been installed on this machine. The installation aborted."
			return_func 1
			return 1
		fi
	fi

	checking_lsattr "${INSTALL_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_lsattr "${CONFIG_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi

	hostname=$(get_hostname)
	info_logging "System checking $(green "SUCCEEDED")."
	
	return 0
}

setup_parameters_read() {
	#parse setup parameters from ./config/setup.conf
	local SETUP_CONFIG_PATH="$SCRIPT_PATH/config/setup.conf"

	ES_USERNAME=$(get_ini "${SETUP_CONFIG_PATH}" "" UserName)
	ES_PASSWORD=$(get_ini "${SETUP_CONFIG_PATH}" "" Password)
	ES_DATAPATH=$(get_ini "${SETUP_CONFIG_PATH}" "" DataPath)
	
	checking_customized_path "${ES_DATAPATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi	
	
	
	ES_LOGPATH=$(get_ini "${SETUP_CONFIG_PATH}" "" LogPath)
	
	checking_customized_path "${ES_LOGPATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	
	if [[ "${upgradeflag}" == "true" ]]; then
		info_logging "ES is in the peroid of upgrading, use the previous datapath and logpath."
	else
		ES_DATAPATH=$(append_folder_name "${ES_DATAPATH}" "${FOLDER_NAME}")
		ES_LOGPATH=$(append_folder_name "${ES_LOGPATH}" "${FOLDER_NAME}")
	fi
	
	ES_BINDIP=$(get_ini "${SETUP_CONFIG_PATH}" "" BindIp)
	ES_PORT=$(get_ini "${SETUP_CONFIG_PATH}" "" Port)
	ES_CPULIMIT=$(get_ini "${SETUP_CONFIG_PATH}" "" CPULimit)
	ES_MEMORYLIMIT=$(get_ini "${SETUP_CONFIG_PATH}" "" MemoryLimit)
	ES_USESSL=$(get_ini "${SETUP_CONFIG_PATH}" "" UseSSL)
	ES_SINGLENODE=$(get_ini "${SETUP_CONFIG_PATH}" "" SingleNode)
	ES_CLUSTERMEMBERS=$(get_ini "${SETUP_CONFIG_PATH}" "" ClusterMembers)
	ES_CIPHERS=$(get_ini "${SETUP_CONFIG_PATH}" "" Ciphers)
	ES_MASTERONLYNODE=$(get_ini "${SETUP_CONFIG_PATH}" "" MasterOnlyNode)
	ES_CLUSTERNAME="elasticsearch"
	if [[ "$ES_USESSL" == "yes" ]] || [[ "${upgradeflag}" == "true" ]]; then
		ES_PRIVATEKEY=$(get_ini "${SETUP_CONFIG_PATH}" "" PrivateKey)
		ES_CERTIFICATE=$(get_ini "${SETUP_CONFIG_PATH}" "" Certificate)
		ES_CERTAUTH=$(get_ini "${SETUP_CONFIG_PATH}" "" CertAuth)
	else
		ES_PRIVATEKEY=./config/key.pem
		ES_CERTIFICATE=./config/cert.pem
		ES_CERTAUTH=./config/cacert.pem
	fi

	if [ ! -f "${ES_PRIVATEKEY}" ] || [ ! -f "${ES_CERTIFICATE}" ] || [ ! -f "${ES_CERTAUTH}" ]; then
		if [[ "${IS_SUBJECT}" == "jkstrue" ]] && [[ "${upgradeflag}" == "true" ]]; then
			warn_logging "The previous ES version uses jks file, replacing them with the default certificates..."
			ES_PRIVATEKEY=./config/key.pem
			ES_CERTIFICATE=./config/cert.pem
			ES_CERTAUTH=./config/cacert.pem
		else
			error_logging "Some of the certificate file is missing: ${ES_PRIVATEKEY} ${ES_CERTIFICATE} ${ES_CERTAUTH}."
			error_logging "The installation aborted."
			return 1
		fi
	fi
	
	if [[ "${upgradeflag}" == "true" ]]; then
		ES_CLUSTERNAME=$(get_ini "${SETUP_CONFIG_PATH}" "" ClusterName)
		ES_NODENAME=$(get_ini "${SETUP_CONFIG_PATH}" "" NodeName)
	fi
	
	return 0
}

setup_parameters_checking() {
	#parse setup parameters from ./config/setup.conf
	local SETUP_CONFIG_PATH="$SCRIPT_PATH/config/setup.conf"

	info_logging "Starting to perform configuration parameters checking..."
	setup_parameters_read
	if [ $? -ne 0 ]; then
		return 1
	fi
	local cpucount=$(get_cpu_count)
	#install path checking
	#local PATH_TYPES=(["1"]="folder" ["2"]="file")
	#local install_path_status=$(get_path_status "${INSTALL_PATH}")
	#if [[ $install_path_status -ne 0 ]]; then
	#warn_logging "The install path [${INSTALL_PATH}] is a ${PATH_TYPES[$install_path_status]} and exists."
	#warn_logging "If you want to continue, we will backup these data into ${SCRIPT_PATH}/backup/install_path/ folder and continue to install, otherwise the installation aborted"
	#read -p "Please input yes or y to continue:" backup
	#if [[ $(toLowerCase ${backup}) != "yes" ]] && [[ $(toLowerCase ${backup}) != "y" ]]; then
	#    error "You choosed discontinue the installtion. The installation aborted."
	#    return_func 1
	#    break
	#fi
	#mkdir -p "${SCRIPT_PATH}/backup/install_path/" || verify_operation
	#mv -f "${INSTALL_PATH}" "${SCRIPT_PATH}/backup/install_path/." || verify_operation
	#fi

	checking_yesno "${ES_USESSL}" "UseSSL"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_yesno "${ES_SINGLENODE}" "SingleNode"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_yesno "${ES_MASTERONLYNODE}" "MasterOnlyNode"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_customized_path "${ES_DATAPATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_customized_path "${ES_LOGPATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_lsattr "${ES_DATAPATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_lsattr "${ES_LOGPATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	create_directory "${ES_DATAPATH}" "DataPath"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	create_directory "${ES_LOGPATH}" "LogPath"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi

	freespaceinMB_data=$(get_disk_available_size "${ES_DATAPATH}")
	freespaceinMB_log=$(get_disk_available_size "${ES_LOGPATH}")
	#freespaceinMB_bin=$(get_disk_available_size "/bin")
	freespaceinMB_usr=$(get_disk_available_size "/usr")
	freespaceinMB_etc=$(get_disk_available_size "/etc")
	

	checking_username "${ES_USERNAME}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi

	if [[ "${ES_USERNAME}" == \#* ]] || [[ "${ES_USERNAME}" == \!* ]]; then
		error_logging "The first character of UserName cannot be ! or #. The installation aborted."
		return_func 1
		return 1
	fi

	checking_password "${ES_PASSWORD}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	if [[ "${ES_PASSWORD}" == \#* ]] || [[ "${ES_PASSWORD}" == \!* ]]; then
		error_logging "The first character of Password cannot be ! or #. The installation aborted."
		return_func 1
		return 1
	fi

	#if [[ -z "${IS_UPGRADE}" ]]; then
	if [[ "${upgradeflag}" == "false" ]]; then
		checking_mem_limitation "${ES_MEMORYLIMIT}"
		if [ $? -ne 0 ]; then
			error_logging "$(get_last_error) The installation aborted."
			return 1
		fi
		checking_cpu_limitation "${ES_CPULIMIT}"
		if [ $? -ne 0 ]; then
			error_logging "$(get_last_error) The installation aborted."
			return 1
		fi
		# Port checking
		#check_portlist "${ES_PORT}"
		checking_RFC1700_port "${ES_PORT}" "${COMPONENT_NAME}"
		if [ $? -ne 0 ]; then
			error_logging "$(get_last_error) The installation aborted."
			return 1
		fi
		checking_RFC1700_port "9300" "${COMPONENT_NAME}"
		if [ $? -ne 0 ]; then
			error_logging "$(get_last_error) The installation aborted."
			return 1
		fi
	fi

	ActualCpuLimit=$(get_percent_value "${ES_CPULIMIT}")
	Cpulimitnum=$(echo "${ActualCpuLimit}" | cut -d "%" -f1)

	if [ "$freespaceinMB_log" -lt "10240" ]; then
		warn_logging "The specified directory ${ES_LOGPATH} has less than 10GB free space, which may result in abnormal use after the Elasticsearch runs for a period of time."
	fi
	if [ "$freespaceinMB_data" -lt "51200" ]; then
		warn_logging "The specified directory ${ES_DATAPATH} has less than 50GB free space, which may result in abnormal use after the Elasticsearch runs for a period of time."
	fi

	#if [ "$freespaceinMB_bin" -lt "500" ]; then
    #            warn_logging "The /bin directory has less than 500MB free space, it is better to extend the related file system ."
    #    fi

	if [ "$freespaceinMB_usr" -lt "2048" ]; then
                warn_logging "The /usr directory has less than 2GB free space, it is better to extend the related file system."
        fi
	
	if [ "$freespaceinMB_etc" -lt "500" ]; then
                warn_logging "The /etc has less than 500MB free space, it is better to extend the related file system."
        fi



	if [ "${Cpulimitnum}" -lt 25 ]; then
		error_logging "The value of the CPULimit parameter cannot be less than 25%. The installation aborted."
		return_func 1
		return 1
	else
		if [ "${Cpulimitnum}" -gt 35 ]; then
			warn_logging "The current value of the CPULimit parameter exceeds the recommended value (35%)."
		fi
	fi

	if [ "$ES_SINGLENODE" == "no" ]; then
		commanum=0
		testmember=$(echo "${ES_CLUSTERMEMBERS}" | awk -F "," '{print $NF}')
		for ((i = 0; i < "${#ES_CLUSTERMEMBERS}"; i++)); do
			TEMP="${ES_CLUSTERMEMBERS:$i:1}"
			if [ "${TEMP}" == "," ]; then
				commanum=$(($commanum + 1))
			fi
		done
		if [ "${commanum}" -eq 0 ]; then
			error_logging "The ClusterMembers is invalid. The installation aborted."
			return_func 1
			return 1
		fi
		if [ "${commanum}" -eq 1 ] && [ -z "${testmember}" ]; then
			error_logging "The ClusterMembers is invalid. The installation aborted."
			return_func 1
			return 1
		fi
		
		if [[ "${ES_CLUSTERMEMBERS}" =~ "127.0.0.1" ]] || [[ "${ES_CLUSTERMEMBERS}" =~ "0.0.0.0" ]]; then
			error_logging "The ClusterMembers is invalid. The installation aborted."
			return_func 1
			return 1
		
		fi
	fi

	checking_bindipv4 "$ES_BINDIP" "$SETUP_CONFIG_PATH"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi

	#add_port_to_firewall "${ES_PORT}"
	#add_port_to_firewall "9300"

	checking_certificate "${ES_CERTIFICATE}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_certificate_key "${ES_PRIVATEKEY}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	checking_certificate "${ES_CERTAUTH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi

	info_logging "HostName is : ${hostname}"
	info_logging "User value is : ${ES_USERNAME}"
	info_logging "Password value is : ******"
	info_logging "DataPath value is : ${ES_DATAPATH}"
	info_logging "LogPath value : ${ES_LOGPATH}"
	info_logging "BindIp value : ${ES_BINDIP}"
	info_logging "Port value : ${ES_PORT}"
	info_logging "CPULimit value is : ${ES_CPULIMIT}"
	info_logging "MemoryLimit value is : ${ES_MEMORYLIMIT}"
	info_logging "UseSSL value is : ${ES_USESSL}"
	info_logging "PrivateKey value is : ${ES_PRIVATEKEY}"
	info_logging "Certificate value is : ${ES_CERTIFICATE}"
	info_logging "CertAuth value : ${ES_CERTAUTH}"
	info_logging "SingleNode value is : ${ES_SINGLENODE}"
	ES_SINGLENODE=$(echo ${ES_SINGLENODE} | tr '[:upper:]' '[:lower:]')
	if [ "${ES_SINGLENODE}" != "yes" ]; then
		info_logging "ClusterMembers value is : ${ES_CLUSTERMEMBERS}"
	fi
	info_logging "Ciphers value is : ${ES_CIPHERS}"
	info_logging "MasterOnlyNode value is : ${ES_MASTERONLYNODE}"
	info_logging "Configuration parameters checking $(green "SUCCEEDED")."
	
	return 0
}

install_official_rpm() {
	info_logging "Starting to perform official rpm package installing..."
	
	rpm -ivh "${SCRIPT_PATH}"/sources/"${RPM_PACKAGE_NAME}"

	"${INSTALL_PATH}"/bin/elasticsearch-plugin install -b file:"${SCRIPT_PATH}/sources/search-guard-flx-elasticsearch-plugin-1.1.0-es-8.5.3.zip" >>"${INSTALL_LOG}"

	yes | cp "${SCRIPT_PATH}"/sources/sgctl.sh "${pluginspath}"/tools

	mkdir -p "$INSTALL_PATH/temp"

	info_logging "Official rpm package installing $(green "SUCCEEDED")."
	
	return 0
}

config_setup_setting() {
	info_logging "Starting to perform configuration parameters updating..."
	local elasticsearch_conf="$CONFIG_PATH/elasticsearch.yml"

	if [ "$ES_USESSL" == "yes" ]; then
		ES_USESSL="true"
	else
		ES_USESSL="false"
	fi

	PRIVATEKEY=$(basename "${ES_PRIVATEKEY}")
	CERTIFICATE=$(basename "${ES_CERTIFICATE}")
	CERTAUTH=$(basename "${ES_CERTAUTH}")

	if [[ -n "${IS_SUBJECT}" ]] && [[ "${IS_SUBJECT}" =~ ','  ]]; then
                CERT_SUBJECT="${IS_SUBJECT}"
    else
		testCA=$(openssl x509 -noout -in "${ES_CERTIFICATE}" -subject)
		echo $testCA				
		#preprocess the output of openssl command based upon the openssl version
		rpm -qa |grep openssl|grep -w el8
        if [ $? -ne 0 ]; then
            testCA="${testCA#*/}"
            testCA="${testCA//,/\\,}"
        else
            testCA="${testCA#*subject=}"
            testCA="${testCA// = /=}"
            info_logging "${testCA}"
            testCA="${testCA//,/\/}"
            testCA="${testCA//\/ /\/}"
            info_logging "${testCA}"
        fi


		result=$(echo "${testCA}" | awk -F'/emailAddress=' '{print $2}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="emailAddress=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},emailAddress=${result}"
			fi
			testCA=$(echo "${testCA}" | awk -F'/emailAddress=' '{print $1}')
		fi

		result=$(echo "${testCA}" | awk -F'/CN=' '{print $2}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="CN=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},CN=${result}"
			fi
			testCA=$(echo "${testCA}" | awk -F'/CN=' '{print $1}')
		fi

		result=$(echo "${testCA}" | awk -F'/OU=' '{print $4}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="OU=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},OU=${result}"
			fi
		fi

		result=$(echo "${testCA}" | awk -F'/OU=' '{print $3}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="OU=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},OU=${result}"
			fi
		fi

		result=$(echo "${testCA}" | awk -F'/OU=' '{print $2}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="OU=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},OU=${result}"
			fi
			testCA=$(echo "${testCA}" | awk -F'/OU=' '{print $1}')
		fi

		result=$(echo "${testCA}" | awk -F'/O=' '{print $2}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="O=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},O=${result}"
			fi
			testCA=$(echo "${testCA}" | awk -F'/O=' '{print $1}')
		fi

		result=$(echo "${testCA}" | awk -F'/street=' '{print $3}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="STREET=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},STREET=${result}"
			fi
		fi

		result=$(echo "${testCA}" | awk -F'/street=' '{print $2}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="STREET=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},STREET=${result}"
			fi
			testCA=$(echo "${testCA}" | awk -F'/street=' '{print $1}')
		fi

		result=$(echo "${testCA}" | awk -F'/L=' '{print $2}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="L=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},L=${result}"
			fi
			testCA=$(echo "${testCA}" | awk -F'/L=' '{print $1}')
		fi

		result=$(echo "${testCA}" | awk -F'/ST=' '{print $2}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="ST=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},ST=${result}"
			fi
			testCA=$(echo "${testCA}" | awk -F'/ST=' '{print $1}')
		fi

		result=$(echo "${testCA}" | awk -F'/postalCode=' '{print $2}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="OID.2.5.4.17=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},OID.2.5.4.17=${result}"
			fi
			testCA=$(echo "${testCA}" | awk -F'/postalCode=' '{print $1}')
		fi

		result=$(echo "${testCA}" | awk -F'/DC=' '{print $3}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="DC=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},DC=${result}"
			fi
		fi

		result=$(echo "${testCA}" | awk -F'/DC=' '{print $2}')
		if [ -n "${result}" ]; then
			if [ -z "${CERT_SUBJECT}" ]; then
				CERT_SUBJECT="DC=${result}"
			else
				CERT_SUBJECT="${CERT_SUBJECT},DC=${result}"
			fi
			testCA=$(echo "${testCA}" | awk -F'/DC=' '{print $1}')
		fi

		if [ -n "$testCA" ]; then
			if [ -n "$CERT_SUBJECT" ]; then
				CERT_SUBJECT="${CERT_SUBJECT},${testCA}"
			else
				CERT_SUBJECT="${testCA}"
			fi
		fi

	fi

	# Just backup for the first time.
	if [ ! -e "${elasticsearch_conf}.default" ]; then
		yes | cp -arf "${elasticsearch_conf}" "${elasticsearch_conf}.default"
	fi

	local settingMark=1
	set_yaml "${elasticsearch_conf}" "[cluster.name]" "elasticsearch" && \
	set_yaml "${elasticsearch_conf}" "[node.name]" "${hostname}" && \
	set_yaml "${elasticsearch_conf}" "[path.data]" "${ES_DATAPATH}" && \
	set_yaml "${elasticsearch_conf}" "[path.logs]" "${ES_LOGPATH}" && \
	set_yaml "${elasticsearch_conf}" "[network.host]" "localhost,${ES_BINDIP}" && \
	set_yaml "${elasticsearch_conf}" "[http.port]" "${ES_PORT}" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.enterprise_modules_enabled]" "false" && \
	set_yaml "${elasticsearch_conf}" "[thread_pool.write.queue_size]" "1000" && \
	set_yaml "${elasticsearch_conf}" "[xpack.security.enabled]" "false" && \
	set_yaml "${elasticsearch_conf}" "[xpack.security.enrollment.enabled]" "true" && \
	set_yaml "${elasticsearch_conf}" "[xpack.security.http.ssl].enabled" "false" && \
	set_yaml "${elasticsearch_conf}" "[http.max_content_length]" "500mb" && \
	set_yaml "${elasticsearch_conf}" "[indices.query.bool.max_clause_count]" "200000" && \
	set_yaml "${elasticsearch_conf}" "[thread_pool.search.size]" "50" && \
	#Transport layer TLS
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.transport.pemkey_filepath]" "${PRIVATEKEY}" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.transport.pemcert_filepath]" "${CERTIFICATE}" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.transport.pemtrustedcas_filepath]" "${CERTAUTH}" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.transport.enforce_hostname_verification]" "false" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.transport.enabled_protocols].[0]" "TLSv1.2" && \
	#HTTP/REST layer SSL
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.http.pemkey_filepath]" "${PRIVATEKEY}" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.http.pemcert_filepath]" "${CERTIFICATE}" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.http.pemtrustedcas_filepath]" "${CERTAUTH}" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.http.enabled]" "true" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.ssl.http.enabled_protocols].[0]" "TLSv1.2" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.authcz.admin_dn].[0]" "${CERT_SUBJECT}" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.nodes_dn].[0]" "${CERT_SUBJECT}" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.check_snapshot_restore_write_privileges]" "true" && \
	set_yaml "${elasticsearch_conf}" "[searchguard.restapi.roles_enabled]" "SGS_ALL_ACCESS" && {
		settingMark=0
	}
	if [ "$settingMark" -ne 0 ]; then
		error_logging "Failed to update configuration settings. The installation aborted."
		return_func 1
		return 1
	fi

	local restapiRolesLine=$(cat ${elasticsearch_conf} | grep "searchguard.restapi.roles_enabled:" )
	sed -i "s@${restapiRolesLine}@searchguard.restapi.roles_enabled: [\"SGS_ALL_ACCESS\"]@g" "${elasticsearch_conf}"

	if [[ "${ES_BINDIP}" == "0.0.0.0" ]]; then
		set_yaml "${elasticsearch_conf}" "[network.host]" "${ES_BINDIP}"
	fi

	if [[ "${upgradeflag}" == "true" ]]; then
		set_yaml "${elasticsearch_conf}" "[cluster.name]" "${ES_CLUSTERNAME}"
		set_yaml "${elasticsearch_conf}" "[node.name]" "${ES_NODENAME}"
	fi

	if [ "$ES_SINGLENODE" == "no" ]; then
		i=1
		j=0
		while ((1 == 1)); do
			split=$(echo "${ES_CLUSTERMEMBERS}" | cut -d "," -f$i)
			if [ "$split" != "" ] && [ "$split" != "$split1" ]; then
				((i++))
				set_yaml "${elasticsearch_conf}" "[discovery.zen.ping.unicast.hosts].[$j]" "${split}"
				split1="$split"
				((j++))
			else
				numvalue=$(($j / 2 + 1))
				break
			fi
		done
		set_yaml "${elasticsearch_conf}" "[discovery.zen.minimum_master_nodes]" "${numvalue}"
	fi
	
	if [ -n "$ES_CIPHERS" ]; then
		i=1
		j=0
		while((1==1))  
		do  
			split=$(echo "${ES_CIPHERS}"|cut -d "," -f$i)
			if [ "$split" != "" ] && [ "$split" != "$split1" ]
			then  
				((i++))  
				set_yaml "${elasticsearch_conf}" "[searchguard.ssl.http.enabled_ciphers].[$j]" "${split}"
				split1="$split"
				((j++)) 
			else
				break  
			fi  
		done
	fi


	if [ "$ES_MASTERONLYNODE" == "yes" ]; then
		set_yaml "${elasticsearch_conf}" "[node.data]" "false"
		set_yaml "${elasticsearch_conf}" "[node.ingest]" "false"
	fi

	sh -c "cat>>$CONFIG_PATH/jvm.options<<EOF
-Djna.tmpdir=$INSTALL_PATH/temp
EOF"
	#set_ini "$CONFIG_PATH/jvm.options" "" "-Djna.tmpdir" "$INSTALL_PATH/temp"        error
	set_ini "$CONFIG_PATH/jvm.options" "" "8:-XX:NumberOfGCLogFiles" "10"
	set_ini "$CONFIG_PATH/jvm.options" "" "8:-XX:GCLogFileSize" "5m"
	
	sed -i "s@filecount=32,filesize=64m@filecount=10,filesize=5m@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@/var/log/elasticsearch@$ES_LOGPATH@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@\${ES_TMPDIR}@$INSTALL_PATH/temp@g" "$CONFIG_PATH/jvm.options"

	sed -i "s@-XX:+HeapDumpOnOutOfMemoryError@#-XX:+HeapDumpOnOutOfMemoryError@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@-XX:HeapDumpPath@#-XX:HeapDumpPath@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@9-:-Xlog:gc*@#9-:-Xlog:gc*@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@8-13:-XX:+UseConcMarkSweepGC@#8-13:-XX:+UseConcMarkSweepGC@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@8-13:-XX:CMSInitiatingOccupancyFraction@#8-13:-XX:CMSInitiatingOccupancyFraction@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@8-13:-XX:+UseCMSInitiatingOccupancyOnly@#8-13:-XX:+UseCMSInitiatingOccupancyOnly@g" "$CONFIG_PATH/jvm.options"
	#sed -i "s@# 10-13:-XX:-UseConcMarkSweepGC@10-13:-XX:-UseConcMarkSweepGC@g" "$CONFIG_PATH/jvm.options"
	#sed -i "s@# 10-13:-XX:-UseCMSInitiatingOccupancyOnly@10-13:-XX:-UseCMSInitiatingOccupancyOnly@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@14-:-XX:+UseG1GC@11-:-XX:+UseG1GC@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@14-:-XX:G1ReservePercent@11-:-XX:G1ReservePercent@g" "$CONFIG_PATH/jvm.options"
	sed -i "s@14-:-XX:InitiatingHeapOccupancyPercent@11-:-XX:InitiatingHeapOccupancyPercent@g" "$CONFIG_PATH/jvm.options"
	
	
	
	
	echo "-XX:-UsePerfData" >>${CONFIG_PATH}/jvm.options
	echo "-Djava.net.preferIPv4Stack=true" >>${CONFIG_PATH}/jvm.options
	echo "8-13:-XX:NewRatio=3" >>${CONFIG_PATH}/jvm.options
	echo "-Xlog:gc*=warning,gc+ref=warning,gc+heap=warning,gc+age=warning:file=${ES_LOGPATH}/gc-%p-%t.log:tags,uptime,time,level:filecount=10,filesize=5m" >>${CONFIG_PATH}/jvm.options
    echo "-Xlog:safepoint*=warning:file=${ES_LOGPATH}/safepoints-%p-%t.log:tags,uptime,time,level:filecount=10,filesize=5m" >>${CONFIG_PATH}/jvm.options
	sed -i "s/logger.action.level = debug/logger.action.level = error/g" "$CONFIG_PATH/log4j2.properties"
	#set_ini "$CONFIG_PATH/log4j2.properties" "" "logger.action.level" "error"    error
	sed -i "s/appender.rolling.policies.size.size = 128MB/appender.rolling.policies.size.size = 5MB/g" "$CONFIG_PATH/log4j2.properties"
	sed -i "s/appender.rolling.strategy.action.condition.nested_condition.exceeds = 2GB/appender.rolling.strategy.action.condition.nested_condition.exceeds = 50MB/g" "$CONFIG_PATH/log4j2.properties"
	sed -i "s/appender.deprecation_rolling.policies.size.size = 1GB/appender.deprecation_rolling.policies.size.size = 5MB/g" "$CONFIG_PATH/log4j2.properties"
	sed -i "s/appender.deprecation_rolling.strategy.max = 4/appender.deprecation_rolling.strategy.max = 10/g" "$CONFIG_PATH/log4j2.properties"

	sed -i "s@#JAVA_HOME=@JAVA_HOME=/usr/local/netbrain/jdk@g" /etc/sysconfig/elasticsearch
	sed -i "s@#ES_HOME=/usr/share/elasticsearch@ES_HOME=/usr/share/elasticsearch@g" /etc/sysconfig/elasticsearch
	#sed -i "s@#MAX_MAP_COUNT=262144@MAX_MAP_COUNT=262144@g" /etc/sysconfig/elasticsearch
	set_ini "/etc/sysconfig/elasticsearch" "" "ES_TMPDIR" "\/usr\/share\/elasticsearch\/temp"
	#set_ini "/etc/sysconfig/elasticsearch" "" "JAVA_HOME" "\/usr\/local\/jdk-11.0.1"     error
	
	env_file="/usr/share/elasticsearch/bin/elasticsearch-env"
    echo 'export TMPDIR="/usr/share/elasticsearch/temp"' >> ${env_file}
    echo 'export LIBFFI_TMPDIR="/usr/share/elasticsearch/temp"' >> ${env_file}

	#unstall.sh copy
	#cp -arf $SCRIPT_PATH/others/uninstall.sh $INSTALL_PATH/bin/

	yes | cp -arf "${ES_PRIVATEKEY}" "${CONFIG_PATH}/"
	yes | cp -arf "${ES_CERTIFICATE}" "${CONFIG_PATH}/"
	yes | cp -arf "${ES_CERTAUTH}" "${CONFIG_PATH}/"

	info_logging "Configuration parameters updating $(green "SUCCEEDED")."
	
	return 0
}

assign_permission() {
	info_logging "Starting to perform permission assigning..."
	#make_path_can_read "${INSTALL_PATH}"
	make_all_subfolder_execute "${INSTALL_PATH}"
	make_all_subfolder_execute "$pluginspath"
	make_all_subfolder_execute "$JAVA_HOME"

	make_path_can_read "${CONFIG_PATH}"

	make_path_can_read "${PID_PATH}"

	chmod +x $pluginspath/tools/*.sh
	#chmod -R u+r,u+x,g+r,g+x,o+r,o+x "$JAVA_HOME"
	#chmod -R o+w "${INSTALL_PATH}"/temp
	set_data_path_owner "${CONFIG_PATH}" "elasticsearch" "elasticsearch"
	chmod 600 ${CONFIG_PATH}/*.*
	chmod 750 "$CONFIG_PATH"
	#chmod o+r /etc
	chmod 640 "$CONFIG_PATH"/elasticsearch.yml
	#chown -R elasticsearch:elasticsearch "${INSTALL_PATH}"
	chmod -R o-w "${INSTALL_PATH}"

	set_data_path_owner "${ES_DATAPATH}" "elasticsearch" "elasticsearch"
	set_data_path_permission "${ES_DATAPATH}"
	set_data_path_owner "${ES_LOGPATH}" "elasticsearch" "elasticsearch"
	set_data_path_owner "${INSTALL_PATH}" "elasticsearch" "elasticsearch"
	set_data_path_permission "${ES_LOGPATH}"
	chmod o+x "${ES_LOGPATH}"

	#id netbrain >&/dev/null
	#if [ $? -eq 0 ]; then
	#	usermod -a -G elasticsearch netbrain
		#if [ $? -ne 0 ]; then
		#	echo "Failed to add group. The installation aborted."
		#	return_func 1
		#	break
		#fi
	#fi
	
	if getent passwd netbrain >/dev/null 2>&1; then
		gpasswd -d netbrain elasticsearch
	fi
	
	#id netbrainadmin >&/dev/null
	#if [ $? -eq 0 ]; then
	if getent passwd netbrainadmin >/dev/null 2>&1; then
		usermod -a -G elasticsearch netbrainadmin
		#if [ $? -ne 0 ]; then
		#	echo "Failed to add group. The installation aborted."
		#	return_func 1
		#	break
		#fi
	fi
	
	add_port_to_firewall "${ES_PORT}"
	add_port_to_firewall "9300"
	
	info_logging "Permission assigning $(green "SUCCEEDED")."
			
	return 0
}

config_deamon_setting() {
	info_logging "Starting to perform deamon setting..."
	local SERVICE_FILE="/usr/lib/systemd/system/${SERVICE_NAME}.service"

	# cpu && mem limitation

	#update jvm.options
	if [[ "${ES_MEMORYLIMIT}" =~ "%" ]]; then
		local max_mem=$(calc_mem_limit "${ES_MEMORYLIMIT}")

		# for Elasticsearch, cannot great then 31GB
		if [[ ${max_mem} -gt 31774 ]]; then
			max_mem=31774
		fi

		sed -i "s/^-Xmx[0-9].*/-Xmx${max_mem}m/g" "${CONFIG_PATH}/jvm.options"
		sed -i "s/^-Xms[0-9].*/-Xms${max_mem}m/g" "${CONFIG_PATH}/jvm.options"
	else
		sed -i "s/^-Xmx[0-9].*/-Xmx${ES_MEMORYLIMIT}/g" "${CONFIG_PATH}/jvm.options"
		sed -i "s/^-Xms[0-9].*/-Xms${ES_MEMORYLIMIT}/g" "${CONFIG_PATH}/jvm.options"
	fi

	max_cpu=$(calc_cpu_limit "${ES_CPULIMIT}")
	setting_cpu_limit_in_systemd "${max_cpu}"

	set_systemd "${SERVICE_FILE}" "Service" "Restart" "on-failure"
	set_systemd "${SERVICE_FILE}" "Service" "RestartSec" "60s"

	systemctl enable "${SERVICE_NAME}"
	systemctl daemon-reload

	info_logging "Deamon setting $(green "SUCCEEDED")."
	
	return 0
}

wait_es_startup(){
	for ((i = 0; i < 900; i++)); do
		#systemctl status elasticsearch|grep -w "running" 2>>"${LOG_PATH}"/service_start.log
		if [ -f "$ES_LOGPATH/${ES_CLUSTERNAME}.log" ]; then
			#info_logging "$ES_LOGPATH/${ES_CLUSTERNAME}.log detected"
			break
		else
			#info_logging "$ES_LOGPATH/${ES_CLUSTERNAME}.log has not yet been detected"
			sleep 5s
		fi
	done
	if [ $i -lt 900 ]; then
		return 0
	else
		return 1
	fi
}


updateCertificate() {
        local elasticsearch_conf="$CONFIG_PATH/elasticsearch.yml"
        input=`cat ${INSTALL_LOG} |grep "ERR: CN=" |grep "is not an admin user"|tail -1|cut -d ":" -f 2`
        if [ $? -ne 0 ]; then
                info_logging "It looks the issue is not caused by certificate."
                return 1
        fi
        sg_subject=${input/is not an admin user/}
        sg_subject=`echo ${sg_subject} | sed -e 's/^[[:space:]]*//'`
        info_logging "The CERTIFICATE SUBJECT is ${sg_subject}"
        set_yaml "${elasticsearch_conf}" "[searchguard.authcz.admin_dn].[0]" "${sg_subject}"
        set_yaml "${elasticsearch_conf}" "[searchguard.nodes_dn].[0]" "${sg_subject}"
        chown elasticsearch:elasticsearch ${CONFIG_PATH}/elasticsearch.yml
        systemctl restart elasticsearch
        for((i=0;i<60;i++)); do
                sleep 10s
                ss -nutlp| grep LISTEN|grep 9300
                if [ $? -eq 0 ]; then
                        break
                fi
        done

        #"${pluginspath}"/tools/sgadmin.sh -cd "${pluginspath}"/sgconfig -cacert "${CONFIG_PATH}"/"${CERTAUTH}" -cert "${CONFIG_PATH}"/"${CERTIFICATE}" -key "${CONFIG_PATH}"/"${PRIVATEKEY}" -icl -nhnv >>"${INSTALL_LOG}"
        #if [ $? -eq 0 ]; then
        #        return 0
        #else
        #        return 1
        #fi
		
		for ((i = 0; i < 100; )); do
			tmpnum=$(cat "${INSTALL_LOG}"|grep "ERR"|grep -v -w "Seems you use a node certificate which is also an admin certificate"|wc -l)
			"${pluginspath}"/tools/sgadmin.sh -cd "${pluginspath}"/sgconfig -cacert "${CONFIG_PATH}"/"${CERTAUTH}" -cert "${CONFIG_PATH}"/"${CERTIFICATE}" -key "${CONFIG_PATH}"/"${PRIVATEKEY}" -icl -nhnv >>"${INSTALL_LOG}"
			errnum=$(cat "${INSTALL_LOG}"|grep "ERR"|grep -v -w "Seems you use a node certificate which is also an admin certificate"|wc -l)		
			if [[ ${errnum} -eq ${tmpnum} ]]; then
				cat "${INSTALL_LOG}" | grep "Done with success"
				if [ $? -eq 0 ]; then
					break
				fi
			fi
			sleep 10s
			((i++))
		done
		
		if [[ $i -eq 100 ]]; then
            error_logging "Failed to initialize Search Guard. The installation aborted."
            return 1
		else
			return 0
		fi
}


initialization() {
	local tmpnum=0
	local errnum=0
	local elasticsearch_conf="$CONFIG_PATH/elasticsearch.yml"

	if [ "$ES_SINGLENODE" == "no" ]; then
		info_logging "Connecting to other nodes in the cluster..."
		if [[ "$ES_MASTERONLYNODE" == "no" && "${upgradeflag}" != "true" ]]; then
			info_logging "Please start installation of other nodes to get the whole cluster connected."
			#sleep 10s
		fi
	else
		info_logging "Starting the service of elasticsearch. Please wait..."
		systemctl start elasticsearch > /dev/null 2>&1
		result=""
        while [ "$result" == "" ]; do
			result=$(systemctl status elasticsearch --no-pager | grep "running" )
			info_logging "Starting service result: $result"
			sleep 30
        done
	fi

	# Clean existing credentials
	#SgInternalUsers="${pluginspath}/sgconfig/sg_internal_users.yml"
	#rm -f "$SgInternalUsers"

	rm -f /usr/share/elasticsearch/plugins/search-guard-flx/sgconfig/sg_frontend_multi_tenancy.yml

	export PATH=$PATH:$JAVA_BIN
	"${pluginspath}/tools/sgctl.sh" connect localhost --ca-cert /etc/elasticsearch/cacert.pem --cert /etc/elasticsearch/cert.pem --key /etc/elasticsearch/key.pem -v -k
	"${pluginspath}/tools/sgctl.sh" update-config "/usr/share/elasticsearch/plugins/search-guard-flx/sgconfig"

	if [[ "${ES_USERNAME}" == "admin" ]]; then
		"${pluginspath}/tools/sgctl.sh" update-user "admin" --password "${ES_PASSWORD}"

        if [ $? -ne 0 ]; then
                echo "Failed to update user. The installation aborted."
				return 1
        fi
	else
		"${pluginspath}/tools/sgctl.sh" add-user "${ES_USERNAME}" --backend-roles admin --password "${ES_PASSWORD}"
	fi

	if [[ "${ES_USESSL}" == "false" ]]; then
		local sslHttpLine=$(cat ${elasticsearch_conf} | grep "searchguard.ssl.http.enabled:" )
		sed -i "s@${sslHttpLine}@searchguard.ssl.http.enabled: false@g" "${elasticsearch_conf}"

		#set_yaml "${elasticsearch_conf}" "[searchguard.ssl.http.enabled]" "false"
		info_logging "Restarting the service of elasticsearch. Please wait..."

		systemctl restart elasticsearch > /dev/null 2>&1
		result=""

        while [ "$result" == "" ]; do
			result=$(systemctl status elasticsearch --no-pager | grep "running" )
			info_logging "Restarting service result: $result"
			sleep 30
        done
	fi

	return 0
}

verification() {
	info_logging "Starting to verify connection..."
	export s1=$(echo "${http_proxy}")
	export s2=$(echo "${https_proxy}")
	export http_proxy=""
	export https_proxy=""

	if [ "$ES_USESSL" == "false" ]; then
		testport=$(curl --tlsv1.2 -s -XGET --user "${ES_USERNAME}":"${ES_PASSWORD}" http://localhost:"${ES_PORT}" | grep cluster_name)
		i="1"
		while [[ -z "$testport" ]]; do
			
			info_logging "It is the No.$i time to attempt to connect to the Elasticsearch, please wait..."
			sleep 30s
			testport=$(curl --tlsv1.2 -s -XGET --user "${ES_USERNAME}":"${ES_PASSWORD}" http://localhost:"${ES_PORT}" | grep cluster_name)
			((i++))
			info_logging "$testport"	
		done
	else
		testport=$(curl --tlsv1.2 -k -s -XGET --user "${ES_USERNAME}":"${ES_PASSWORD}" https://localhost:"${ES_PORT}" | grep cluster_name)
		i="1"
		while [[ -z "$testport" ]]; do
			
			info_logging "It is the No.$i time to attempt to connect to the Elasticsearch, please wait..."
			sleep 30s
			testport=$(curl --tlsv1.2 -k -v -XGET --user "${ES_USERNAME}":"${ES_PASSWORD}" https://localhost:"${ES_PORT}" | grep cluster_name)
			((i++))
			info_logging "$testport"
		done
	fi
	
	info_logging "$(green "Successfully") connected to the Elasticsearch. The setup was finished."
	
	sed -i '/=====>/d' "${INSTALL_LOG}"
	export http_proxy="${s1}"
	export https_proxy="${s2}"
	
	return 0
}

postprocessing() {
	nb_backup_uninstall_files "${SCRIPT_PATH}" "${UNINSTALL_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi

	yes | cp -f fix_releaseinfo.json "${INSTALL_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "Failed to save fix_releaseinfo.json. The installation aborted."
		return 1
	fi
	chmod 664 "${INSTALL_PATH}"/fix_releaseinfo.json
	chown elasticsearch:elasticsearch "${INSTALL_PATH}"/fix_releaseinfo.json

	nb_backup_release_info_file "${SCRIPT_PATH}" "${UNINSTALL_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi

	info_logging "Backing up uninstall.sh $(green "SUCCEEDED")."

	nb_restore_setup_conf "${SCRIPT_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi

	#info_logging "Successfully installed ${COMPONENT_NAME}."
	return 0
}

clean() {
	set_user_creation_immutable
	remove_color_in_log
	
	return 0
}

install() {
	# RPM installation
	install_official_rpm
	if [ $? -ne 0 ]; then
		return 1
	fi
	# Config setup
	config_setup_setting
	if [ $? -ne 0 ]; then
		return 1
	fi
	# Permission assignment
	assign_permission
	if [ $? -ne 0 ]; then
		return 1
	fi
	# Config Setting
	config_deamon_setting
	if [ $? -ne 0 ]; then
		return 1
	fi
	# Initialization
	initialization
	if [ $? -ne 0 ]; then
		return 1
	fi
	# Service status checking
	verification
	if [ $? -ne 0 ]; then
		return 1
	fi

	systemctl status "${SERVICE_NAME}" --no-pager 
	teststatus=$(systemctl status ${SERVICE_NAME} --no-pager| grep running)
	if [ -n "$teststatus" ]; then
		info_logging "Successfully installed ${COMPONENT_NAME}. Service is running."
	else
		info_logging "Successfully installed ${COMPONENT_NAME}, but the service cannot be started up."
	fi
	
	# Restarting Service Monitor Agent to make the permission assignment effective.
	restart_serviceMonitor_agent
	if [ $? -ne 0 ]; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	
	return 0
}

main() {
	info_logging "Starting to install ${COMPONENT_NAME} ..."
	system_checking
	if [ $? -ne 0 ]; then
		return 1
	fi
	setup_parameters_checking
	if [ $? -ne 0 ]; then
		return 1
	fi
	#service monitor exists checking
	if ! checking_service_monitor "${SCRIPT_PATH}" "${COMPONENT_NAME}" "${MONITOR_VERSION}" "installation"; then
		error_logging "$(get_last_error) The installation aborted."
		return 1
	fi
	install
	if [ $? -ne 0 ]; then
		return 1
	fi
	
	return 0
}

# return 1 - no installed; 0-installed
comp_is_installed() {
	init_variable "${1}"

	rpm_installed "${RPM_NAME}"
	if [ $? -eq 0 ]; then
		return 0
	fi

	rpm_installed "${BUSINESS_RPM_NAME}"
	if [ $? -eq 0 ]; then
		return 0
	fi

	systemd_service_exists "${SERVICE_NAME}"
	if [ $? -eq 0 ]; then
		return 0
	fi

	grep "Starts and stops a single elasticsearch instance on this system" /etc/init.d/* 2>&1 >/dev/null
	if [ $? -eq 0 ]; then
		return 0
	fi

	return 1
}

comp_get_depend_rpmlist() {
	echo ""
	return 0
}

comp_checking() {
	while true; do
		init_variable "${1}"
		checking_required_cpu 4 
		if [ $? -ne 0 ]; then
			error_logging "$(get_last_error) The installation aborted."
			break
		fi
		checking_required_mem 4096 
		if [ $? -ne 0 ]; then
			error_logging "$(get_last_error) The installation aborted."
			break
		fi
		return 0
	done
	return 1
}

comp_write_config() {
	init_variable "${1}"
	local SETUP_CONFIG_SRC_PATH="${2}"
	local SETUP_CONFIG_PATH="./config/setup.conf"

	#copy content from SETUP_CONFIG_SRC_PATH to SETUP_CONFIG_PATH
	#local dataPath=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "DataPath")
	#local logPath=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "LogPath")
	local user=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "UserName")
	local password=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "Password")
	local datapath=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "DataPath")
	local logpath=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "LogPath")
	local usessl=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "UseSSL")
	local certpath=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "Certificate")
	local keypath=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "PrivateKey")
	local capath=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "CertAuth")
	local bindip=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "ActualIp")
	local port=$(get_ini "$SETUP_CONFIG_SRC_PATH" "global" "ElasticSearchPort")

	set_ini "$SETUP_CONFIG_PATH" "" "UserName" "${user}"
	set_ini "$SETUP_CONFIG_PATH" "" "Password" "${password}"
	set_ini "$SETUP_CONFIG_PATH" "" "UseSSL" "${usessl}"
	set_ini "$SETUP_CONFIG_PATH" "" "BindIp" "${bindip}"
	set_ini "$SETUP_CONFIG_PATH" "" "Port" "${port}"
	set_ini "$SETUP_CONFIG_PATH" "" "DataPath" "${datapath}/elasticsearch"
	set_ini "$SETUP_CONFIG_PATH" "" "LogPath" "${logpath}/elasticsearch"
	if [ "${usessl}" == "yes" ]; then
		set_ini "$SETUP_CONFIG_PATH" "" "Certificate" "${certpath}"
		set_ini "$SETUP_CONFIG_PATH" "" "PrivateKey" "${keypath}"
		set_ini "$SETUP_CONFIG_PATH" "" "CertAuth" "${capath}"
	fi
	
	return 0

}

comp_setup_parameters_checking() {
	while true; do
		init_variable "${1}"
		setup_parameters_checking
		if [ $? -ne 0 ]; then
			break
		fi
		return 0
	done
	return 1
}

comp_install() {
	while true; do
		init_variable "${1}"
		setup_parameters_read
		if [ $? -ne 0 ]; then
			break
		fi
		install
		if [ $? -ne 0 ]; then
			break
		fi
		postprocessing
		if [ $? -ne 0 ]; then
			break
		fi
		info_logging "Succeeded in installing Elasticsearch."
		return 0
	done
	return 1
}

if [[ ${1:0:5} = "comp_" ]]; then
	# echo "call $1"
	"$@"
else
	looptag=true
	while ${looptag}; do
		preprocessing
		if [ $? -ne 0 ]; then
			break
		fi
		info_logging "Start installing Elasticsearch..."
		main
		if [ $? -ne 0 ]; then
			break
		fi
		postprocessing
		if [ $? -ne 0 ]; then
			break
		fi
		info_logging "Succeeded in installing Elasticsearch."
		break
	done

	# Clearance
	clean
fi
