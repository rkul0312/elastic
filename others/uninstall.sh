#!/bin/bash
# IEVersion: 10.1.0
# shellcheck disable=SC2104,SC2155,SC2162,SC2181,SC1091

# Be sure to copy yq to the same directory as uninstall.sh
# Be sure grant yq and uninstall.sh files execute permissions

export IS_LOG="${1}"
export IS_UPGRADE="${2}"

preprocessing() {
	SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	cd "$SCRIPT_PATH" || return 1
	looptag=true

	if [ -d "${SCRIPT_PATH}/include" ]; then
		source "${SCRIPT_PATH}/include/source.sh"
		source "${SCRIPT_PATH}/include/uninstall_au_patch.sh"
	else
		source ../include/source.sh
		source ../include/uninstall_au_patch.sh
	fi

	COMPONENT_NAME="Elasticsearch"
	RPM_NAME="elasticsearch-oss"
	BUSINESS_RPM_NAME="elasticsearch"
	SERVICE_NAME="elasticsearch"
	SERVICE_FILE="/usr/lib/systemd/system/${SERVICE_NAME}.service"
	SERVICE_SAVEFILE="/usr/lib/systemd/system/${SERVICE_NAME}.service.rpmsave"
	INSTALL_PATH="/usr/share/elasticsearch"
	FOLDER_NAME="elasticsearch"
	CONFIG_PATH="/etc/elasticsearch"
	CONFIG_FILE="${CONFIG_PATH}/elasticsearch.yml"
	UNINSTALL_PATH="/usr/lib/netbrain/installer/elasticsearch/"
	INIT_PATH="/etc/init.d/${SERVICE_NAME}/"

	PROCESS="uninstallation"

	checking_root
	if [ $? -ne 0 ]; then
		error "$(get_last_error) The uninstallation aborted."
		return 1
	fi

	if [[ -n "${IS_LOG}" ]]; then
		INSTALL_LOG="${IS_LOG}"
	else
		INSTALL_LOG="$(nb_comp_uninstall_log_filepath $FOLDER_NAME)"
	fi

	if [ ! -f "${INSTALL_LOG}" ]; then
		create_log_file "${INSTALL_LOG}"
		if [ $? -ne 0 ]; then
			error "$(get_last_error) The uninstallation aborted."
			return 1
		else
			info_logging "Creating uninstallation log file $(green "SUCCEEDED")"
		fi
	fi

	if systemd_service_exists "$SERVICE_NAME"; then
		if ! systemctl status "$SERVICE_NAME" | grep -q running >&/dev/null; then
			systemctl start "$SERVICE_NAME" >&/dev/null
			sleep 10s
		fi
	else
		error_logging "The Elasticsearch does not exist. The uninstallation aborted."
		return 1
	fi

	DATA_PATH=$(get_yaml "${CONFIG_FILE}" "[path.data]")
	LOG_PATH=$(get_yaml "${CONFIG_FILE}" "[path.logs]")
	PORT=$(get_yaml "${CONFIG_FILE}" "[http.port]")
	if [[ "${PORT}" == "null" ]]; then
		PORT="9200"
	fi

	info_logging "Component Name: ${COMPONENT_NAME}"
	info_logging "Service name: ${SERVICE_NAME}"
	info_logging "Service file: ${SERVICE_FILE}"
	info_logging "Installation path: ${INSTALL_PATH}"
	info_logging "Config path: ${CONFIG_PATH}"
	info_logging "Data path: ${DATA_PATH}"
	info_logging "Log path: ${LOG_PATH}"
	
	return 0
}

uninstall_rpm() {
	if rpm -qa "${RPM_NAME}" | grep -q "${RPM_NAME}"; then
		rpm -e "${RPM_NAME}" >> "${INSTALL_LOG}" 2>&1
	fi

	if rpm -qa "${BUSINESS_RPM_NAME}" | grep -q "${BUSINESS_RPM_NAME}"; then
		rpm -e "${BUSINESS_RPM_NAME}" || verify_operation
	fi
	
	return 0
}

remove_port() {
	remove_port_from_firewall "${PORT}"
	remove_port_from_firewall "9300"
	return 0
}

remove_all_data() {
	local PATHS=("${CONFIG_PATH}" "${SERVICE_FILE}" "${SERVICE_SAVEFILE}" "${LOG_PATH}" "${DATA_PATH}" "${INSTALL_PATH}" "${INIT_PATH}")
	for p in ${PATHS[*]}; do
		rm -rf "${p}"
		if [ $? -ne 0 ]; then
			error_logging "Failed to remove ${p}. The uninstallation aborted."
			looptag=false
			return 1
		else
			info_logging "Removing ${p} $(green "SUCCEEDED")."
		fi
	done

	if ! ${looptag}; then
		return 1
	fi
	
	return 0
}

main() {

	if [[ "${IS_UPGRADE}" == "allintwo" ]]; then
		uninstall_au_patch "ElasticSearch" "allintwo"
	else
		uninstall_au_patch "ElasticSearch" "notallintwo"
	fi
	if [ $? -eq 99 ]; then
		info_logging "The uninstallation has been canceled by client."
		return 1
	fi

	if [[ -n "${IS_UPGRADE}" ]]; then
		remove="y"
	else
		while true; do
			warn_logging "WARNING: Do you want to remove the data/log/config files after uninstalling the ${COMPONENT_NAME} component?"
			read -p "Input [ yes | y ] if you want to remove the data/log/config files or [ no | n ] otherwise]: " input

			remove=$(checking2_yesno "${input}" "input")
			if [[ "$remove" == "y" ]] || [[ "$remove" == "n" ]]; then
				break	
			fi
		done
	fi
		
	uninstall_rpm
	if [ $? -ne 0 ]; then
		return 1
	fi	
	remove_port
	if [ $? -ne 0 ]; then
		return 1
	fi
	
	if [[ "${remove}" == "y" ]]; then
		remove_all_data
		if [ $? -ne 0 ]; then
			return 1
		fi
	fi

	set_user_creation_immutable
	if [ $? -ne 0 ]; then
		return 1
	fi
	nb_remove_release_info_file "${UNINSTALL_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "${get_last_error} The uninstallation aborted."		
		return 1
	else
		info_logging "Successfully uninstalled ${COMPONENT_NAME}."
	fi
	return 0
}

while ${looptag}; do
	preprocessing
	if [ $? -ne 0 ]; then
		break
	fi
	info_logging "Starting to uninstall Elasticsearch ..."
	main
	if [ $? -ne 0 ]; then
		break
	fi
	nb_remove_uninstall_files "${UNINSTALL_PATH}"
	if [ $? -ne 0 ]; then
		error_logging "${get_last_error} The uninstallation aborted."	
	fi
	break
done
