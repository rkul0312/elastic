#!/bin/bash
# shellcheck disable=SC2104,SC2155,SC2162,SC2181

PROCESS="installation"

set_last_error() {
    LAST_ERR="$1"
}

get_last_error() {
    echo -e "${LAST_ERR}"
}

: <<!
* @description: Pipe function to process failed command
* @return: void
!
verify_function() {
    LAST_ERR=""
    $("$@")
    if [ $? -ne 0 ]; then
        set_last_error "Failed: $@ -- ${LAST_ERR}"
	    looptag=false
        return 1
    fi
}

: <<!
* @description: logging pipe function
* @param stream
* @return: void
!
logging() {
    local logfile="${INSTALL_LOG}"
    while read -r line; do
        echo -e "${line}"
        echo -e "${line}" | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" | tee -a "${logfile}" >/dev/null
    done
}

: <<!
* @description: Add the given string in the log file
* @param action "echo|debug|info|warn|error|fatal"
* @param message
* @param isprint  yes|y|true|ok
* @return: void
!
logging_write() {
    local MARKS=("yes" "y" "true" "ok")
    local action="$1"
    local message=`date +%Y-%m-%d' '%H-%M-%S.%N | cut -b 1-23`": ""$2"
    local isprint="$3"
    local logfile="${INSTALL_LOG}"
    isprint=$(echo "$isprint" | tr '[:upper:]' '[:lower:]')
    is_in_array "${isprint}" "${MARKS[@]}"
    if [ $? -eq 0 ]; then
        if [ "${action}" = "echo" ]; then
            if [[ -f "${logfile}" ]]; then
                echo -e "${message}" | tee -a "${logfile}"
            else
                echo -e "${message}"
            fi
        else
            if [[ -f "${logfile}" ]]; then
                "${action}" "${message}" | tee -a "${logfile}"
            else
                "${action}" "${message}"
            fi
        fi
    else
        if [ "${action}" = "echo" ]; then
            if [[ -f "${logfile}" ]]; then
                echo -e "${message}" >>"${logfile}"
            else
                echo -e "${message}"
            fi
        else
            if [[ -f "${logfile}" ]]; then
                "${action}" "${message}" >>"${logfile}"
            else
                "${action}" "${message}"
            fi
        fi
    fi
}

: <<!
* @description: Add the given string in the log file
* @param message
* @return: void
!
logging_echo() {
    logging_write "echo" "$1"
}

: <<!
* @description: Add the DEBUG: prefix string in the log file
* @param message
* @return: void
!
logging_debug() {
    logging_write "debug" "$1"
}

: <<!
* @description: Add the INFO: prefix string in the log file
* @param message
* @return: void
!
logging_info() {
    logging_write "info" "$1"
}

: <<!
* @description: Add the WARNING: prefix string in the log file
* @param message
* @return: void
!
logging_warn() {
    logging_write "warn" "$1"
}

: <<!
* @description: Add the ERROR: prefix string in the log file
* @param message
* @return: void
!
logging_error() {
    logging_write "error" "$1"
}

: <<!
* @description: Add the FATAL: prefix string in the log file
* @param message
* @return: void
!
logging_fatal() {
    logging_write "fatal" "$1"
}

: <<!
* @description: Echo the given string and logging it in the log file
* @param message
* @return: void
!
echo_logging() {
    logging_write "echo" "$1" "yes"
}

: <<!
* @description: Echo the debug string and logging it in the log file
* @param message
* @return: void
!
debug_logging() {
    logging_write "debug" "$1" "yes"
}

: <<!
* @description: Echo the info string and logging it in the log file
* @param message
* @return: void
!
info_logging() {
    logging_write "info" "$1" "yes"
}

: <<!
* @description: Echo the warning string and logging it in the log file
* @param message
* @return: void
!
warn_logging() {
    logging_write "warn" "$1" "yes"
}

: <<!
* @description: Echo the error string and logging it in the log file
* @param message
* @return: void
!
error_logging() {
    logging_write "error" "$1" "yes"
}

: <<!
* @description: Echo the fatal string and log it into the log file
* @param message
* @return: void
!
fatal_logging() {
    logging_write "fatal" "$1" "yes"
}

#---------------------------

: <<!
* @description: Pipe function to process failed command
* @return: void
!
verify_operation() {
    local result=$?
    if [ $result -ne 0 ]; then
        echo "Operation failed. The ${PROCESS} aborted." # Jack
	    looptag=false
        return 1
    fi
}

: <<!
* @description: Create a log file for the given file path
* @param message
* @return: void
!
create_log_file() {
    local log="$1"
    # /1/*.log
    if [ ${#log} -lt 8 ]; then
        set_last_error "The file path is invalid." # Jack
	    looptag=false
        return 1
    fi
    if [ -e "${log}" ]; then
        mv "${log}" "${log}.`date +%Y%m%d%H%M%S`"
        if [ -e "${log}" ]; then
            set_last_error "Failed to rename old file."
			looptag=false
			return 1
        fi
    fi
    local path=$(dirname "${log}")
    mkdir -p "${path}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        set_last_error "Failed to create the directory."
	    looptag=false
        return 1
    fi
    touch "${log}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        set_last_error "Failed to create the file."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Create a directory for the given path
* @param message
* @return: void
!
create_directory() {
    local path="$1"
    local dirname="$2"
    # /1/*.log
    if [ -z "${path}" ]; then
        set_last_error "The ${path} parameter is empty."
	    looptag=false
        return 1
    fi
    if [ ! -d "${path}" ]; then
        mkdir -p "${path}"
        if [ $? -ne 0 ]; then
            set_last_error "Failed to create the directory for ${dirname}."
			looptag=false
			return 1
        fi
    fi
    return 0
}

: <<!
* @description: Check if a directory is a file.
* @param path
* @return: 0/1
!
checking_path_is_file() {
    local path="$1"

    if [ -f "${path}" ]; then
        return 0
    else
        return 1
    fi
}

: <<!
* @description: Check if a directory is writable.
* @param path
* @return: 0/1
!
checking_path_is_writable() {
    local path="$1"

    if [ -w "${path}" ]; then 
        return 0
    else
        return 1
    fi
}

: <<!
* @description: Check if the current user has root privileges
* @return: void
!
checking_root() {
    if ! is_root; then
        set_last_error "You need root privileges to continue."
	    looptag=false
        return 1
    fi

    unset_user_creation_immutable
    return 0
}

: <<!
* @description: Collecting system information and output to log file
* @return: void
!
collecting_system_info() {
    _collecting_system_info() {
        echo "  Collecting system information..."
        echo "            Kernel: $(uname -a)"
        echo "       Logged User: $(who -m | awk '{print $1;}')"
        echo "              Date: $(date)"
        hostnamectl

        local COMMANDS=("cat /etc/redhat-release" "env" "rpm -qa" "lscpu" "df" "/usr/sbin/sestatus -v")
        #echo "Length = " ${#COMMANDS[@]}
        for ((i = 0; i < ${#COMMANDS[@]}; i++)); do
            echo -e "===""${COMMANDS[i]}""==="
            echo -e "$(${COMMANDS[i]})"
        done
    }
    local info=$(_collecting_system_info)
    logging_write "info" "${info}" "no"

    info_logging "Collecting system information $(green "SUCCEEDED")."
    return 0
}

: <<!
* @description: Checking if current OS is RedHat/CentOS 7.x or 8.x version and 64-bit
* @return: void
!
checking_os() {
    is_rhel_or_centos || is_amzn || is_alma || is_rocky
    if [[ $? -ne 0 ]]; then
        set_last_error "The operating system must be Alma Linux, Amazon Linux, RedHat Linux, Oracle Linux, Rocky Linux or CentOS Linux."
	    looptag=false
        return 1        
    fi

    is_rhel7x || is_amzn2 || is_rhel8x || is_alma || is_rocky
    if [[ $? -ne 0 ]]; then
        set_last_error "The version of the operating system must be Alma Linux, Amazon Linux 2, RedHat Linux, Oracle Linux, Rocky Linux or CentOS Linux 7.5, 7.6, 7.7, 7.8, 7.9, 8.0, 8.1, 8.2, 8.3, 8.4, 8.5 or 8.6. For online upgrades, refer to https://www.netbraintech.com/docs/ie100/Linux_System_Upgrade_Instructions_Online.pdf. For offline upgrades, refer to https://www.netbraintech.com/docs/ie100/Linux_System_Upgrade_Instructions_Offline.pdf."
	    looptag=false
        return 1
    fi

    is_x86_64
    if [[ $? -ne 0 ]]; then
        set_last_error "The operating system must be 64-bit."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Checking if current OS meets the given CPU requirements
* @param cpu
* @return: void
!
checking_required_cpu() {
    local cpu="$1"
    if [ -z "$cpu" ]; then
        set_last_error "The cpu parameter is empty."
	    looptag=false
        return 1
    fi
    if ! is_int "${cpu}"; then
        set_last_error "The CPU parameter ( ${cpu} ) is not a valid integer."
	    looptag=false
        return 1
    fi

    local total
    total=$(get_cpu_count)
    if [[ "$total" -lt "$cpu" ]]; then
        set_last_error "The total CPU core number ${total} of current server is less than required minimum core number ${cpu}."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Checking if current OS meets the given memory requirements
* @param mem
* @return: void
!
checking_required_mem() {
    local mem="$1"
    if [ -z "$mem" ]; then
        set_last_error "The mem parameter is empty."
	    looptag=false
        return 1
    fi
    if ! is_int "${mem}"; then
        set_last_error "The mem parameter ( ${mem} ) is not a valid integer."
	    looptag=false
        return 1
    fi

    local total
    total=$(get_memory)
    if [[ "$total" -lt "$mem" ]]; then
        set_last_error "The total memory of current server is less than required minimum memory size ${mem}MB."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Checking if the available disk size of the given path meets the given disk size requirements
* @param path The path needs to be checked
# @param disksize Minimum disk size in MB unit
* @return: void
!
checking_required_disksize() {
    local path="$1"
    local disksize="$2"

    if [ -z "$path" ]; then
        set_last_error "The path parameter is empty."
	    looptag=false
        return 1
    fi
    if [ -z "$disksize" ]; then
        set_last_error "The disksize parameter is empty."
	    looptag=false
        return 1
    fi
    if ! is_int "${disksize}"; then
        set_last_error "The disksize parameter ( ${disksize} ) is not a valid integer."
	    looptag=false
        return 1
    fi

    local availableSize
    availableSize=$(get_disk_available_size "${path}")
    if [[ "$availableSize" -lt "$disksize" ]]; then
        set_last_error "The available disk size of the given path is less than required minimum disk size ${disksize}MB."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Checking if the given rpm has already been installed
* @param RPM_NAME
* @param COMPONENT_NAME
* @return: void
!
checking_rpm_exists() {
    local RPM_NAME="$1"
    local COMPONENT_NAME="$2"

    if [ -z "$RPM_NAME" ]; then
        set_last_error "The RPM name parameter is empty."
	    looptag=false
        return 1
    fi
    if [ -z "$COMPONENT_NAME" ]; then
        set_last_error "The component name parameter is empty."
	    looptag=false
        return 1
    fi

    if rpm_installed "${RPM_NAME}"; then
        set_last_error "${COMPONENT_NAME} has already been installed on this machine. If you believe that ${COMPONENT_NAME} has not been installed, please uninstall the rpm package ${RPM_NAME}."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Checking if the given systemd service has already been installed
* @param SERVICE_NAME
* @param COMPONENT_NAME
* @return: void
!
checking_systemd_exists() {
    local SERVICE_NAME="$1"
    local COMPONENT_NAME="$2"

    if [ -z "$SERVICE_NAME" ]; then
        set_last_error "The service name parameter is empty."
	    looptag=false
        return 1
    fi
    if [ -z "$COMPONENT_NAME" ]; then
        set_last_error "The component name parameter is empty."
	    looptag=false
        return 1
    fi

    if systemd_service_exists "${SERVICE_NAME}"; then
        set_last_error "The service of ${COMPONENT_NAME} has already been installed on this machine. If you believe that ${COMPONENT_NAME} has not been installed, please uninstall the service ${SERVICE_NAME}."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Checking if the given systemd service has not been installed
* @param SERVICE_NAME
* @param COMPONENT_NAME
* @return: void
!
checking_systemd_not_exists() {
    local SERVICE_NAME="$1"
    local COMPONENT_NAME="$2"

    if [ -z "$SERVICE_NAME" ]; then
        set_last_error "The service name parameter is empty."
	    looptag=false
        return 1
    fi
    if [ -z "$COMPONENT_NAME" ]; then
        set_last_error "The component name parameter is empty."
	    looptag=false
        return 1
    fi

    if ! systemd_service_exists "${SERVICE_NAME}"; then
        set_last_error "The service of ${COMPONENT_NAME} has not been installed on this machine."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Checking if the OS's system clock is earlier than package's date
* @return: void
!
checking_date() {
    is_valid_ntpdate
    if [[ $? -ne 0 ]]; then
        set_last_error "The current system time is earlier than the creation time of the ${PROCESS} package. Please modify the system time and try again."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Checking if the given string is a valid integer
* @param VALUE
* @param VALUE_NAME
* @return: void
!
checking_int() {
    local VALUE="$1"
    local VALUE_NAME="$2"

    if [ -z "$1" ]; then
        set_last_error "The value parameter is empty."
	    looptag=false
        return 1
    fi
    if [ -z "$2" ]; then
        VALUE_NAME="parameter"
    fi

    if ! is_int "${VALUE}"; then
        set_last_error "The ${VALUE_NAME} must be an integer."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Check if the given path is immutable
* @param path
* @return: void
!
checking_lsattr() {
    local path="$1"
    if [ -z "$1" ]; then
        set_last_error "The path parameter is empty."
	    looptag=false
        return 1
    fi

    if [[ "$1" != /* ]]; then
        set_last_error "The path parameter is not an absolute path."
	    looptag=false
        return 1
    fi

    while [[ "${path}" != "/" ]]; do
        if ! is_lsattr "${path}"; then
            set_last_error "The directory ${path} is immutable."
			looptag=false
			return 1
        fi
        path="$(dirname "$path")"
    done
    return 0
}

: <<!
* @description: Create a log file for the given file path
* @path string
* @return: void
!
checking_customized_path() {
    local path="$1"
    if [ -z "$1" ]; then
        set_last_error "The path parameter is empty."
	    looptag=false
        return 1
    fi
    local parent=$(dirname "${path}")
    if [[ "$parent" == "/" ]]; then
        set_last_error "The path (${path}) is invalid, it should be at least 2 level directory."
	    looptag=false
        return 1
    fi

    if [ -f "${path}" ]; then
        set_last_error "The path (${path}) is invalid, it cannot be a file."
	    looptag=false
        return 1
    fi
    return 0
}

checking_root_path() {
    local path="$1"
    local name="$2"
    local parent=$(dirname "${path}")
    if [[ "$parent" == "/" ]]; then
        set_last_error "The path (${path}) for $name is invalid, it should be at least 2 level directory."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Check if the given port is valid
* @param port
* @param COMPONENT_NAME
* @return: void
!
checking_port() {
    local port="$1"
    local COMPONENT_NAME="$2"
    if [ -z "$port" ]; then
        set_last_error "The port parameter is empty."
	    looptag=false
        return 1
    fi
    if [ -z "$COMPONENT_NAME" ]; then
        COMPONENT_NAME="The component"
    fi

    is_valid_port "${port}"
    if [[ $? -ne 0 ]]; then
        set_last_error "The Port must be between 0 and 65535."
	    looptag=false
        return 1
    fi

    is_port_using "${port}"
    if [[ $? -ne 0 ]]; then
        set_last_error "${COMPONENT_NAME} needs an internal port: ${port}, but it's in use."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Check if the given port is a valid RFC1700 port
* @param port
* @param COMPONENT_NAME
* @return: void
!
checking_RFC1700_port() {
    local port="$1"
    local COMPONENT_NAME="$2"
    if [ -z "$port" ]; then
        set_last_error "The port parameter is empty."
	    looptag=false
        return 1
    fi
    if [ -z "$COMPONENT_NAME" ]; then
        COMPONENT_NAME="The component"
    fi

    is_valid_RFC1700_port "${port}"
    if [[ $? -ne 0 ]]; then
        set_last_error "The Port must be between 1025 and 32767."
	    looptag=false
        return 1
    fi

    is_port_using "${port}"
    if [[ $? -ne 0 ]]; then
        set_last_error "${COMPONENT_NAME} needs an internal port: ${port}, but it's in use."
	    looptag=false
        return 1
    fi
    return 0
}

checking_RFC1700_portlist() {
    local COMPONENT_NAME="$1"
    local port
    shift

    local portlist=("$@")
    for port in $portlist; do
        checking_RFC1700_port "$port"
        if [[ $? -ne 0 ]]; then
			looptag=false
			return 1
        fi
    done
    return 0
}

: <<!
* @description: Check if the given string is a valid username
* @param USERNAME
* @return: void
!
checking_username() {
    local USERNAME="$1"
    local teststr
    is_valid_username "$USERNAME"
    teststr=$?
    case $teststr in
    1)
        set_last_error "The UserName should not be empty."
	    looptag=false
        return 1
        ;;
    2)
        set_last_error "The UserName should not contain a space."
	    looptag=false
        return 1
        ;;
    3)
        set_last_error "The UserName should not contain: {}[]:\",'|<>@&^%\\."
	    looptag=false
        return 1
        ;;
    4)
        set_last_error "The length of the UserName should not exceed 64 characters."
	    looptag=false
        return 1
        ;;
    esac
    return 0
}

: <<!
* @description: Check if the given string is a valid password
* @param PASSWORD
* @return: void
!
checking_password() {
    local PASSWORD="$1"
    local teststr
    is_valid_password "$PASSWORD"
    teststr=$?
    case $teststr in
    1)
        set_last_error "The Password should not be empty."
	    looptag=false
        return 1
        ;;
    2)
        set_last_error "The Password should not contain a space."
	    looptag=false
        return 1
        ;;
    3)
        set_last_error "The Password should not contain: {}[]:\",'|<>@&^%\\."
	    looptag=false
        return 1
        ;;
    4)
        set_last_error "The length of the Password should not exceed 64 characters."
	    looptag=false
        return 1
        ;;
    esac
    return 0
}

:<<!
* @description: validate the password
* @param PASSWORD
* @return 0/1
!

checking_password_policy() {
     local testPassword="$1"
        
        if [[  -z "$testPassword" ]]; then
                set_last_error "The Password should not be empty."
                looptag=false
                return 1
        elif [[ "$testPassword" =~ " " ]]; then
                set_last_error "The Password should not contain a space."
                looptag=false
                return 1
        elif [[ "$testPassword" == *[{}\[\]:\",\'\|@^\&\<\>%\\]* ]]; then
                set_last_error "The Password should not contain: {}[]:\",'|<>@&^%\\."
                looptag=false
                return 1
        elif [[ "${#testPassword}" -gt 64 ]]; then
                set_last_error "The length of the Password should not exceed 64 characters."
                looptag=false
                return 1
        elif [[ "${#testPassword}" -lt 8 ]]; then
                set_last_error "The length of the Password should not be less than 8 characters."
                looptag=false
                return 1
        else
        return 0
    fi
        return 0
}



:<<!
* @description: Check if the given string is a valid username
* @param USERNAME
* @return: void
!
checking_apikey() {
    local APIKEY="$1"
    local teststr
    is_valid_password "$APIKEY"
	teststr=$?
	case "$teststr" in
		1)
		set_last_error "The API key should not be empty."
	    looptag=false
        return 1
        break
		;;
		2)
		set_last_error "The API key should not contain a space."
	    looptag=false
        return 1
        break
		;;
		3)
		set_last_error "The API key should not contain: {}[]:\",'|<>@&^%\\."
	    looptag=false
        return 1
        break
		;;
		4)
		set_last_error "The length of the API key should not exceed 64 characters."
	    looptag=false
        return 1
        break
		;;
	esac
    return 0
}

: <<!
* @description: Check if the given dependencies are all installed
* @param COMPONENT_NAME
* @param rpms
* @return: void
!
checking_runtime_dependencies() {
    if [ -z "$1" ]; then
        set_last_error "The component name is empty."
	    looptag=false
        return 1
    fi
    if [ -z "$2" ]; then
        set_last_error "The rpm list parameter is empty."
	    looptag=false
        return 1
    fi
	if [ -n "$3" ]; then
        local PROCESS="$3"
    fi
    local COMPONENT_NAME="$1"
    local rpms="$2"
    local length
    local inexistent_rpms
    local packagename
    packagename="dependencies-$(get_os)$(get_os_version).tar.gz"
    # inexistent_rpms=($(get_inexistent_rpms "${rpms}"))
    IFS=" " read -r -a inexistent_rpms <<<"$(get_inexistent_rpms "${rpms}")"
    length=${#inexistent_rpms[@]}
    if ((length > 0)); then
        _error_ret() {
            local COMPONENT_NAME="$1"
            shift
            local inexistent_rpms=("$@")
            error "To perform ${COMPONENT_NAME}'s ${PROCESS}, the following dependencies are required."
            echo "Missing dependencies: ${inexistent_rpms[*]}"
            echo "Please choose one of the following two options to install the dependencies."
            echo "  1) Online install: "
            echo "      Run \"yum -y install ${inexistent_rpms[*]}\" to download the dependencies online and install them."
            echo "  2) Offline install:"
            echo "      Download the dependency package from an internet-enabled server using \"http://download.netbraintech.com/${packagename}\"."
            echo "      Copy the downloaded dependency package from the other server to this server."
            echo "      Run tar -zxvf ${packagename} to decompress the package"
            echo "      Run offline-install.sh within the decompressed directory to install the dependencies."
            echo "Re-run the install.sh or upgrade.sh after installing all of the dependencies."
        }

        set_last_error "$(_error_ret "${COMPONENT_NAME}" ${inexistent_rpms[@]})"
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Check if the python's dependencies are all installed
* @param COMPONENT_NAME
* @return: void
!
checking_python_runtime_dependencies() {
    checking_runtime_dependencies "$1" "zlib-devel readline-devel bzip2-devel ncurses-devel gdbm-devel xz-devel tk-devel libffi-devel gcc" "$2"
}

: <<!
* @description: Check if the give CPU limitation value is valid
* @param CPU_LIMIT
* @return: void
!
checking_cpu_limitation() {
    local CPU_LIMIT="$1"
    if [ -z "$CPU_LIMIT" ]; then
        set_last_error "The CPU limitation parameter is empty."
	    looptag=false
        return 1
    fi

    is_valid_cpu_limitation "${CPU_LIMIT}"
    if [[ $? -ne 0 ]]; then
        set_last_error "Current component's CPU limitation value (${CPU_LIMIT}) is not a valid value [range(1%-100%)]."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Check if the give memory limitation value is valid
* @param MEM_LIMIT
* @return: void
!
checking_mem_limitation() {
    local MEM_LIMIT="$1"
    if [ -z "$MEM_LIMIT" ]; then
        set_last_error "The memory limitation parameter is empty."
	    looptag=false
        return 1
    fi

    is_valid_mem_limitation "${MEM_LIMIT}"
    if [[ $? -ne 0 ]]; then
        set_last_error "Current component's memory limitation value (${MEM_LIMIT}) is not a valid value [range(1%-100%)]."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Set CPU limitation in systemd service file
* @param VALUE
* @return: void
!
setting_cpu_limit_in_systemd() {
    local SERVICE_FILE="/usr/lib/systemd/system/${SERVICE_NAME}.service"
    # SERVICE_FILE="${SCRIPT_PATH}/config/nbagent.service"
    local SECTION="Service"
    local KEY="CPUQuota"
    local VALUE="$1"
    if [ -z "$VALUE" ]; then
        set_last_error "The CPU limitation parameter is empty."
	    looptag=false
        return 1
    fi
    #echo "${SERVICE_FILE}" "${SECTION}" "${KEY}" "${VALUE}"
    set_systemd "${SERVICE_FILE}" "${SECTION}" "${KEY}" "${VALUE}"
    if [[ $? -ne 0 ]]; then
        set_last_error "Failed to modify CPU limitation setting."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Set memory limitation in systemd service file
* @param VALUE
* @return: void
!
setting_mem_limit_in_systemd() {
    local SERVICE_FILE="/usr/lib/systemd/system/${SERVICE_NAME}.service"
    # SERVICE_FILE="${SCRIPT_PATH}/config/nbagent.service"
    local SECTION="Service"
    local KEY="MemoryLimit"
    local VALUE="${1}M"
    if [ -z "${1}" ]; then
        set_last_error "The CPU limitation parameter is empty."
	    looptag=false
        return 1
    fi
    #echo "${SERVICE_FILE}" "${SECTION}" "${KEY}" "${VALUE}"
    set_systemd "${SERVICE_FILE}" "${SECTION}" "${KEY}" "${VALUE}"
    if [[ $? -ne 0 ]]; then
        set_last_error "Failed to modify memory limitation setting."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Check if the give certificate file is valid
* @param path
* @return: void
!
checking_certificate() {
    local path="$1"
    if [ -z "${path}" ]; then
        set_last_error "The certificate file parameter is empty."
	    looptag=false
        return 1
    fi
    if [ ! -e "${path}" ]; then
        set_last_error "The certificate file ${path} does not exist."
	    looptag=false
        return 1
    fi
    openssl x509 -in "${path}" -text -noout >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        set_last_error "The certificate file ${path} is invalid."
	    looptag=false
        return 1
    fi
    openssl x509 -checkend 0 -noout -in "${path}"
    if [ $? -ne 0 ]; then
        set_last_error "The certificate ${path} is expired."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Check if the give private key file is valid
* @param path
* @return: void
!
checking_certificate_key() {
    local path="$1"
    if [ -z "${path}" ]; then
        set_last_error "The private key file parameter is empty."
	    looptag=false
        return 1
    fi
    if [ ! -e "${path}" ]; then
        set_last_error "The private key file ${path} does not exist."
	    looptag=false
        return 1
    fi
    openssl rsa -in "${path}" -text -noout >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        set_last_error "The private key file ${path} is invalid."
	    looptag=false
        return 1
    fi
    return 0
}

checking_crontab() {
    crontab -l | sed "$ a 0 */12 * * * netbrain-cron-validate" | crontab >/dev/null 2>&1

    if [ ! $? == 0 ]; then
        set_last_error "The cron file is corrupted, please fix this file first and then continue."
	    looptag=false
        return 1
    else
        crontab -l | sed "/netbrain-cron-validate/d" | crontab >/dev/null 2>&1
    fi
    return 0
}

: <<!
* @description: Check if the give parameter is valid
* @param value
* @param parameter name
* @return: void
!
checking_yesno() {
    local MARKS=("yes" "no")
    local value="$1"
    local parameter_name="$2"
    is_in_array "${value}" "${MARKS[@]}"
    if [ $? -ne 0 ]; then
        set_last_error "The ${parameter_name} parameter is invalid, it can be only 'yes' or 'no'."
	    looptag=false
        return 1
    fi
    return 0
}

: <<!
* @description: Check if the give parameter is valid
* @param value
* @param parameter name
* @return: void
!
checking2_yesno() {
    local MARKS=("yes" "y" "no" "n")
    local value=$(toLowerCase "$1")
    local parameter_name="$2"
    is_in_array "${value}" "${MARKS[@]}"
    if [ $? -ne 0 ]; then
        if [ -z "${parameter_name}" ]; then
            echo "The parameter is invalid, it can be only yes|y|no|n. "
        else
            echo "The ${parameter_name} parameter is invalid, it can be only yes|y|no|n. "
        fi
	    looptag=false
        return 1
    fi

    if [[ "${value}" == "yes" || "${value}" == "y" ]]; then
        echo "y"
    else
        echo "n"
    fi

    return 0
}

: <<!
* @description: End User License Agreement (EULA) checking
!
checking_eula() {
    local eulaConfirm="NULL"
    while [[ $(toUpperCase "${eulaConfirm}") != "YES" ]] && [[ $(toUpperCase "${eulaConfirm}") != "NO" ]]; do
        echo ""
        read -p "Please read the End User License Agreement ('EULA') for the license type (perpetual or subscription) purchased in the order form at https://www.netbraintech.com/legal-tc/ carefully. I have read the subscription EULA, if I have purchased a subscription license, or the perpetual EULA, if I have purchased a perpetual license, at the link provided above. Please type 'YES' if you have read the applicable EULA and understand its contents, or 'NO' if you have not read the applicable EULA. [YES/NO]:" eulaConfirm
    done
    if [[ $(toUpperCase "${eulaConfirm}") == "NO" ]]; then
        set_last_error "Please first read the applicable EULA and run the script again."
	    looptag=false
        return 1
    fi

    local eulaAccept="NULL"
    while [[ $(toUpperCase "${eulaAccept}") != "I ACCEPT" ]] && [[ $(toUpperCase "${eulaAccept}") != "CANCEL" ]]; do
        echo ""
        read -p "Do you accept the terms in the subscription EULA, if you have purchased a subscription license, or the perpetual EULA, if you have purchased a perpetual license? If you accept, and to continue with the installation, please type 'I ACCEPT' to continue. If you do not accept, and to quit the installation script, please type 'CANCEL' to stop. [I ACCEPT/CANCEL]:" eulaAccept
    done
    if [[ $(toUpperCase "${eulaAccept}") == "CANCEL" ]]; then
        set_last_error "You have chosen to cancel the process."
	    looptag=false
        return 1
    fi
    return 0
}

checking_letter_number() {
    local input="$1"
    local name="$2"
    if [[ ! ${input} =~ ^[a-zA-Z][a-zA-Z0-9_]+$ ]]; then
        set_last_error "The ${name} should only be letters and numbers and start with a letter."
	    looptag=false
        return 1
    fi
    return 0
}

checking_bindipv4() {
    local bindip="$1"
    local conf="$2"

    if [ -z "${bindip}" ]; then
        set_last_error "Please fill out the actual IP address in $conf."
	    looptag=false
        return 1
    fi

    if [[ "$bindip" == "127.0.0.1" ]]; then
        set_last_error "Please fill out the actual IP address in $conf(loopback address 127.0.0.1 is not allowed)."
	    looptag=false
        return 1
    fi

    if [[ ! "$bindip" == "0.0.0.0" ]]; then
        #$(hostname -I | grep "^"'${bindip}'" ")
        if [[ ! $(hostname -I | grep "${bindip} ") ]]; then
            set_last_error "Please fill out the actual IP address in $conf."
	    looptag=false
        return 1
        fi
    fi
    return 0
}

checking_masternode() {
    local bindip="$1"
    local path="$2"

    if [ -z "${bindip}" ]; then
        set_last_error "The ${path} parameter is empty."
	    looptag=false
        return 1
    fi

    if [[ "$bindip" == "127.0.0.1" ]]; then
        set_last_error "The loopback address 127.0.0.1 is not allowed for ${path}."
	    looptag=false
        return 1
    fi

    if [[ "$bindip" == "0.0.0.0" ]]; then
        set_last_error "The universal address 0.0.0.0 is not allowed for ${path}."
	    looptag=false
        return 1
    fi
    return 0
}

checking_ssl_files() {
	local CERTFILE="$1"
	local KEYFILE="$2"
	local CACERTFILE="$3"
	
	# Cert checking
	if ! checking_certificate "${CERTFILE}"; then
		return 1
	fi

	# Key checking
	if ! checking_certificate_key "${KEYFILE}"; then
		return 1
	fi

	if [ -n "$3" ]; then
        # CA Cert checking
	    if ! checking_certificate "${CACERTFILE}"; then
		    return 1
    	fi
        #make sure the cert verified by CA
        if ! openssl verify -CAfile "${CACERTFILE}" "${CERTFILE}" >/dev/null 2>&1; then
            set_last_error "The certificate can not be verified with given Certificate Authority (CA) file. Please bundle the chain certificates by appending to CA file if exists."
            return 1
        fi
    fi
	
	#make sure the cert modulus matched with key modulus
	cert_modulus=$(openssl  x509 -noout -modulus -in "${CERTFILE}" | openssl sha256 | awk 'NR==1{print $2}')
	key_modulus=$(openssl rsa -noout -modulus -in "${KEYFILE}" | openssl sha256 | awk 'NR==1{print $2}')
	if [[ "$key_modulus" != "$cert_modulus" ]]; then
		set_last_error "The private key file is not matched with certificate."
		return 1
	fi
	return 0
}

#################################################
# @param $1: MONITOR_SCRIPTS_PATH
# @echo: checking Service Monitor Agent
#################################################
checking_service_monitor() {
	local SM_PATH="$1"
	local COMPONENT="$2"
	local VERSION="$3"
	local rpmlist=""
	local PROCESS="$4"

	if ! checking_os; then
        error "$(get_last_error) The ${PROCESS} was aborted."
        return 1
    fi
	#call comp_get_depend_rpmlist
	echo "Getting rpm dependency list of ${COMPONENT} and Service Monitor Agent..."
	rpmlist=`sh "${SM_PATH}/install.sh" comp_get_depend_rpmlist`
	if [ $? -ne 0 ]; then
		return 1
	fi
	rpmlist="${rpmlist} zlib-devel readline-devel bzip2-devel ncurses-devel gdbm-devel xz-devel tk-devel libffi-devel gcc"

	if [ -n "${rpmlist}" ]; then
		checking_runtime_dependencies "${COMPONENT} and Service Monitor Agent" "${rpmlist}" "${PROCESS}"
		if [ $? -ne 0 ]; then
			set_last_error "$(get_last_error)"
			return 1
		fi
    fi

    if ! checking_systemd_not_exists "netbrainagent" "Service Monitor Agent"; then
        if ! tar -xf "${SM_PATH}/sources/netbrain-servicemonitoragent-linux-x86_64-rhel-${VERSION}.tar.gz" -C "${SM_PATH}"; then
		    set_last_error "Failed to extract service monitor agent tar file."
		    return 1
	    fi 
        chmod 644 "${SM_PATH}/ServiceMonitorAgent/config/setup.conf"
		set_ini "${SM_PATH}/ServiceMonitorAgent/config/setup.conf" "" "single" "no"
		set_ini "${SM_PATH}/ServiceMonitorAgent/config/setup.conf" "" "Main_component" "${COMPONENT}"

        if ! nb_install_monitor "${SM_PATH}/ServiceMonitorAgent"; then
            set_last_error "$(get_last_error)"
            return 1
        fi
    else
        #SM_OLD_VERSION=$(grep SoftwareVersion "/usr/share/nbagent/fix_releaseinfo.json" 2>&1 | cut -d ":" -f3 | cut -d "\"" -f2)
        #if [[ "$SM_OLD_VERSION" != "${SOFTWARE_VERSION}" ]]; then
		if nb_is_1010_from_releaseinfo "/usr/share/nbagent/fix_releaseinfo.json" ; then
			info_logging "The latest Service Monitor Agent version has been installed."
		else
            if ! tar -xf "${SM_PATH}/sources/netbrain-servicemonitoragent-linux-x86_64-rhel-${VERSION}.tar.gz" -C "${SM_PATH}"; then
                set_last_error "Failed to extract service monitor agent tar file."
                return 1
            fi
            chmod 644 "${SM_PATH}/ServiceMonitorAgent/config/setup.conf"
            set_ini "${SM_PATH}/ServiceMonitorAgent/config/setup.conf" "" "single" "no"
            set_ini "${SM_PATH}/ServiceMonitorAgent/config/setup.conf" "" "Main_component" "${COMPONENT}"

            if ! nb_upgrade_monitor "${SM_PATH}/ServiceMonitorAgent"; then
                set_last_error "$(get_last_error)"
                return 1
            fi
        fi
    fi
	
	looptag=true
	return 0
}

restart_serviceMonitor_agent() {
	if [[ -f "/usr/lib/systemd/system/netbrainagent.service" ]]; then
		if ! systemctl restart netbrainagent >/dev/null 2>&1; then
            set_last_error "Failed to restart netbrainagent service."
        fi
		for (( i = 0 ; i < 300 ; i++));do
			systemctl status netbrainagent |grep "running" >/dev/null 2>&1	
			if [ $? -eq 0 ]; then
				info_logging "The netbrainagent service has been restarted."
				break
			else
				info_logging "Waiting for netbrainagent service to be running."
				sleep 1s
			fi
		done		
	fi
    return 0
}
