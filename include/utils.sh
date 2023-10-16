#!/bin/bash
# shellcheck disable=SC1091,SC2104,SC2155,SC2162,SC2181,SC2216

:<<!
* @description: Command return function
* @param return_code
* @return: 0|1|code
!
return_func()
{
    local return_code="$1"
    #if [ $1 = "0" ];then return 0;else return 1;fi;
    looptag=false    
    return "${return_code}"
}

:<<!
* @description: Format the given string in red color
* @param string
* @return: echo
!
red() {
    local START='\033[0;31m'
    local END='\033[0m'
    echo -e "${START}$1${END}"
}

:<<!
* @description: Format the given string in green color
* @param string
* @return: echo
!
green() {
    local START='\033[0;32m'
    local END='\033[0m'
    echo -e "${START}$1${END}"
}

:<<!
* @description: Format the given string in yellow color
* @param string
* @return: echo
!
yellow() {
    local START='\033[0;33m'
    local END='\033[0m'
    echo -e "${START}$1${END}"
}

:<<!
* @description: Echo the given string with "DEBUG:" prefix
* @param string
* @return: echo
!
debug () {
    echo -e "DEBUG: $1"
}

:<<!
* @description: Echo the given string with "INFO:" prefix
* @param string
* @return: echo
!
info () {
    echo -e "INFO: $1"
}

:<<!
* @description: Echo the given string with "WARNING:" prefix
* @param string
* @return: echo
!
warn(){
    local START='\033[0;33m'
    local END='\033[0m'
    echo -e "${START}WARNING: $1${END}"
}

:<<!
* @description: Echo the given string with "ERROR:" prefix
* @param string
* @return: echo
!
error() {
    local START='\033[0;31m'
    local END='\033[0m'
    echo -e "${START}ERROR: $1${END}"
}

:<<!
* @description: Echo the given string with "FATAL:" prefix
* @param string
* @return: echo
!
fatal () {
    local START='\033[0;31m'
    local END='\033[0m'
    echo -e "${START}FATAL: $1${END}"
}

:<<!
* @description: lowercase the given string
* @param string
* @return: echo
!
toLowerCase() {    
    echo "$1" | tr '[:upper:]' '[:lower:]'
}

:<<!
* @description: Transfer the given string to uppercase
* @param string
* @return: echo
!
toUpperCase() {
    echo "$1" | tr '[:lower:]' '[:upper:]'
}

:<<!
* @description: Check if the given string is a valid integer
* @param string
* @return: 0|1
!
is_int() {
	local reg_int='^[0-9]+([.][0-9]+)?$'
    if [[ "$1" =~ $reg_int ]]; then return 0;else return 1; fi
}

:<<!
* @description: Check if the given string is a valid number
* @param string
* @return: 0|1
!
is_number() {
	local reg_number='^[+-]?[0-9]+([.][0-9]+)?$'
    if [[ "$1" =~ $reg_number ]]; then return 0;else return 1; fi
}

:<<!
* @description: Check if the given element is in the given array
* @param string
* @param array
* @return: 0|1
!
is_in_array() {
   local item="$1"
   shift 
   local arrays=("$@")
   match=1
   for acc in "${arrays[@]}";do
	    if [ "$acc" = "$item" ]; then
		match=0
		break
	    fi
          
   done
   return "$match"
}

:<<!
* @description: Check the given string in which status
* @param string
* @return: 0|1|2|3|4 ok|empty|contains space|contains special character | more than 64 bytes
!
check_string() {
	local teststring="$1"
    local value=0
	if [  -z "$teststring" ]; then 
		value=1;
	elif [[ "$teststring" =~ " " ]]; then 
		value=2;
	elif [[ "$teststring" == *[{}\[\]:\",\'\|@^\&\<\>%\\]* ]]; then 
		value=3;
	elif [[ ${#teststring} -gt 64 ]]; then 
		value=4;
	else
        value=0;
    fi
	echo $value
}

:<<!
* @description: Check if the given string is a valid username
* @param string
* @return: 0|1|2|3|4 ok|empty|contains space|contains special character | more than 64 bytes
!
is_valid_username() {
    return "$(check_string "$1")"
}

:<<!
* @description: Check if the given string is a valid password
* @param string
* @return: 0|1|2|3|4 ok|empty|contains space|contains special character | more than 64 bytes
!
is_valid_password() {
    return "$(check_string "$1")"
}

:<<!
* @description: Check if the given string is a valid URL
* @param string
* @return: 0|1
!
is_valid_url() {
    local REGEX='https?://(www.)?[-a-zA-Z0-9@%._\+~#=]{2,256}(|:[1-9][0-9]{0,3}|:[1-5][0-9]{4}|:6[0-4][0-9]{3}|:65[0-4][0-9]{2}|:655[0-2][0-9]|:6553[0-5])(/|\?)([-a-zA-Z0-9@:%_\+.~#?&//=!]*)'
    local URL="$1"
    if [[ $URL =~ $REGEX ]]; then return 0;else return 1; fi
}

:<<!
* @description: Remove un-unicode color string in the log file
* @return: void
!
remove_color_in_log() {
    if [ -f "${INSTALL_LOG}" ]; then
        sed -i "s,\x1B\[[0-9;]*[a-zA-Z],,g" "${INSTALL_LOG}" >/dev/null 2>&1
        # https://www.commandlinefu.com/commands/view/3584/remove-color-codes-special-characters-with-sed
    fi
    # this is a hack for looptag setting, becuase we need recover the looptag value to true.
    looptag=true
}

:<<!
* @description: Parse the integer value from the given percent like xy%
* @param percent
* @return: integer
!
get_percent_value() {
    local percent="$1"
    local REGEX="^[0-9]+%$"
    local last=${percent: -1}
    if [[ "$percent" =~ $REGEX ]];then
        local percentValue=$(echo "${percent}" | cut -d "%" -f1)    
        if is_number "${percentValue}";then
            echo "${percentValue}"
        else
            echo ""
        fi
    else
        echo ""
    fi
}

:<<!
* @description: Check if the given percent value is a valid CPU limitation
* @param percent
* @return: 0|1
!
is_valid_cpu_limitation() {    
    local percentValue="$(get_percent_value "$1")"
    local maxValue=$(($(get_cpu_count)*100))
    if [[ ${percentValue} -gt 0 ]] && [[ ${percentValue} -le 100 ]]; then
        return 0
    else 
        return 1
    fi
}

:<<!
* @description: Check if the given percent value is a valid memory limitation
* @param percent
* @return: 0|1
!
is_valid_mem_limitation() {
    local percentValue=$(get_percent_value "$1")
    if [[ ${percentValue} -gt 0 ]] && [[ ${percentValue} -le 100 ]]; then
        return 0
    else 
        return 1
    fi
}

:<<!
* @description: Calc the CPU core limiation value
* @param percent Range(1%-100%)
* @return: percent
!
calc_cpu_limit() {
	local percent="$1"
    local cpucount=$(get_cpu_count)
    local percentValue=$(echo "${percent}" | cut -d "%" -f1)
    if [[ ${percentValue} -le 100 ]]; then
        echo "$((cpucount * percentValue))%"
    else
	    echo "${percentValue}%"
    fi
}

:<<!
* @description: Calc the memory limitaion value in MB unit
* @param percent Range(1%-100%)
* @return: integer Unit: MB
!
calc_mem_limit() {
	local percent="$1"
    local totalmem=$(get_memory)
    local percentValue=$(echo "${percent}" | cut -d "%" -f1)
    echo "$((totalmem * percentValue / 100))"
}

:<<!
* @description: Get the start line number of the given section in the given ini file
* @param file
* @param section
* @return: integer
!
get_section_start_line_no() {
    local file="$1"
    local section="$2"
    if [ -z "${section}" ]; then
        echo 1
    else
        #cat "${file}" | sed -n "/^\[${section}\]/=" | head -n 1
        local lone_no
        lone_no=$(awk '/^\['"${section}"'\]/{a=1} (a==1){print NR}' "${file}" | head -n 1)
        echo "$((lone_no + 1))"
    fi
}

:<<!
* @description: Get the end line number of the given section in the given ini file
* @param file
* @param section
* @return: integer
!
get_section_end_line_no() {
    local file="$1"
    local section="$2"
    local start_line_no=$(get_section_start_line_no "${file}" "${section}")
    #cat "${file}" | sed -n "/^\[${section}\]/=" | head -n 1
    local interval=$(tail -n +"$((start_line_no + 1))" "${file}" | awk '/^\[.*\]/{a=1} (a==1){print NR}' | head -n 1)
    if [ -z "${interval}" ]; then
        awk 'END{print NR}' "${file}"
    else
        echo "$((start_line_no+interval-1))"
    fi    
}

:<<!
* @description: Get the value of the given section && key in the given ini file
* @param file
* @param section
* @param key
* @return: string
!
get_ini() {
    local file="$1"
    local section="$2"
    local key="$3"
    local start_line_no=$(get_section_start_line_no "${file}" "${section}")
    local end_line_no=$(get_section_end_line_no "${file}" "${section}")
    # echo "${start_line_no}" "->" "${end_line_no}"    
    tail -n +"${start_line_no}" "${file}" | head -n "$((end_line_no - start_line_no + 1 ))" | sed  -e "/^${key}=.*/!d" -e "s/^${key}=//" -e 's/^ *//' -e 's/ *$//' | head -n 1
}

:<<!
* @description: Set the value of the given section && key in the given ini file
* @param file
* @param section
* @param key
* @param value
* @return: void
!
set_ini() {
    local file="$1"
    local section="$2"
    local key="$3"
    local value="$4"
    local start_line_no=$(get_section_start_line_no "${file}" "${section}")
    local end_line_no=$(get_section_end_line_no "${file}" "${section}")
    #echo $start_line_no "->" $end_line_no
    local curr_line=$(awk "NR>=${start_line_no} && NR<=${end_line_no}" "${file}" | awk "/^${key}\=.*/{print NR}")
    #echo "${curr_line}"
    if [[ ${end_line_no} -eq 0 ]]; then
        echo "${key}=${value}" > "${file}"
    elif [ -z "${curr_line}" ]; then
        #echo "new"
        sed -i "${end_line_no}a\\${key}\=${value}" "${file}"
    else
        #echo "replace"
        sed -i "$((curr_line + start_line_no -1 ))i\\${key}\=${value}" "${file}"
        sed -i "$((curr_line + start_line_no ))d" "${file}"
    fi
}

:<<!
* @description: Get the value of the given section && key in the given systemd service file
* @param file
* @param section
* @param key
* @return: string
!
get_systemd() {
    local file="$1"; local section="$2"; local key="$3";
    get_ini "${file}" "${section}" "${key}"
}

:<<!
* @description: Set the value of the given section && key in the given systemd service file
* @param file
* @param section
* @param key
* @param value
* @return: void
!
set_systemd() {
    local file="$1"; local section="$2"; local key="$3"; local val="$4"
    set_ini "${file}" "${section}" "${key}" "${val}"
}

:<<!
* @description: Get the value of the given key in the given yaml file
* @param file
* @param key
* @return: string
!
get_yaml() {
	local file="${1}"
	local key="${2}"
	"$(dirname "${BASH_SOURCE[0]}")/yq" r "${file}" "${key}"
}

:<<!
* @description: Set the value of the given key in the given yaml file
* @param file
* @param key
* @param value
* @return: void
!
set_yaml() {
	local file="${1}"
    local key="${2}"
	local value="${3}"
	"$(dirname "${BASH_SOURCE[0]}")/yq" w -i "${file}" "${key}" "${value}"
}

:<<!
* @description: Get the value of the given key in the given setup.conf file
* @param file
* @param key
* @return: string
!
get_setup_conf() {
    local file="${1}"
	local key="${2}"
    get_ini "${file}" "" "${key}"
}

:<<!
* @description: Add a port in the firewall whitelist
* @param port
* @return: void
!
add_port_to_firewall() {
    local port="$1"
    is_valid_port "${port}"
    local r1=$?
    systemd_service_exists "firewalld"
    local r2=$?
    local zone="public"
    if [ $r1 -eq 0 ] && [ $r2 -eq 0 ]; then        
        if ! systemctl status firewalld --no-pager | grep "dead" >/dev/null 2>&1; then
            zone=$(firewall-cmd --get-active-zones | head -1)
            firewall-cmd --zone="${zone}" --add-port="${port}"/tcp --permanent > /dev/null 2>&1
            systemctl unmask firewalld
            systemctl restart firewalld.service
        else
            systemctl unmask firewalld
            systemctl start firewalld.service
            zone=$(firewall-cmd --get-active-zones | head -1)
            firewall-cmd --zone="${zone}" --add-port="${port}"/tcp --permanent > /dev/null 2>&1
            systemctl restart firewalld.service
            systemctl stop firewalld.service
        fi    
    fi
    return 0
}

:<<!
* @description: Remove a port in the firewall whitelist
* @param port
* @return: void
!
remove_port_from_firewall() {
    local port="$1"
    is_valid_port "${port}"
    local r1=$?
    systemd_service_exists "firewalld"
    local r2=$?
    local zone="public"
    if [ $r1 -eq 0 ] && [ $r2 -eq 0 ]; then        
        if ! systemctl status firewalld  --no-pager | grep "dead" >/dev/null 2>&1; then
            zone=$(firewall-cmd --get-active-zones | head -1)
            firewall-cmd --zone="${zone}" --remove-port="${port}"/tcp --permanent > /dev/null 2>&1
            systemctl unmask firewalld
            systemctl restart firewalld.service
        else
            systemctl unmask firewalld
            systemctl start firewalld.service
            zone=$(firewall-cmd --get-active-zones | head -1)
            firewall-cmd --zone="${zone}" --remove-port="${port}"/tcp --permanent > /dev/null 2>&1
            systemctl restart firewalld.service
            systemctl stop firewalld.service
        fi    
    fi
    return 0
}

:<<!
* @description: Add a port in the firewall whitelist
* @param port
* @return: void
!
add_portlist_to_firewall() {

	local portlist=("$@")
	local port
	for port in $portlist
	do
		add_port_to_firewall "${port}"
		if [ $? -ne 0 ]; then
			set_last_error "${port} is not added to firewall"
			return 1
		fi		
	done
    return 0
}

:<<!
* @description: Remove a port in the firewall whitelist
* @param port
* @return: void
!
remove_portlist_from_firewall() {
	local portlist=($@)
	local port
	for port in $portlist
	do
		remove_port_from_firewall "${port}"
		if [ $? -ne 0 ]; then
			set_last_error "${port} is not removed from firewall"
			return 1
		fi		
	done
    return 0	
}

:<<!
* @description: Ensure that all parent folders in a given path have read permission
* @param path
* @return: void
!
set_parents_path_read() {
    local path="$1"
    local pdir
    pdir="$(dirname "$path")"
    while [[ "${pdir}" != "/" ]]; do
        #echo "${pdir}"
        chmod u+r,o+r,o+x "${pdir}" #>/dev/null 2>&1
        pdir="$(dirname "$pdir")"
    done 
    return 0
}

:<<!
* @description: Ensure that the given path has read permission on user/group/other groups
* @param path
* @return: void
!
make_path_can_read() {
    local path="$1"
    if [ ${#path} -ge 1 ];then
        set_parents_path_read "${path}" #>/dev/null 2>&1  # all parents can read
        chmod -R u+r,g+r,g+x,o+r,o+x "${path}" #>/dev/null 2>&1 # install path and sub path
    fi
    return 0
}

:<<!
* @description: Ensure that the all sub folders are given execute permission on user/group/other groups
* @param path
* @return: void
!
make_all_subfolder_execute() {
    local path="$1"
    if [ ${#path} -ge 1 ];then
        set_parents_path_read "${path}" #>/dev/null 2>&1  # all parents can read
        find "${path}" -type d -iname "*" -exec chmod u+r,g+r,g+x,o+r,o+x {} \;   #>/dev/null 2>&1 # install path and sub path
    fi
    return 0
}


:<<!
* @description: Assign the given account as owner for a given path
* @param path
* @return: void
!
set_data_path_owner() {
    local path="$1"
    local account="$2"
    local group="$3"
    if [ ${#path} -ge 1 ];then
        set_parents_path_read "${path}" #>/dev/null 2>&1 # all parents can read
        chown -R "${account}":"${group}" "${path}" #>/dev/null 2>&1 # install path and sub path
    fi
    return 0
}

:<<!
* @description: Ensure that the given path has 644 permission
* @param path
* @return: void
!
set_data_path_permission() {
    local path="$1"
    if [ ${#path} -ge 1 ];then
        set_parents_path_read "${path}" #>/dev/null 2>&1 # all parents can read
        chmod -R u+r,u+w,u+x,g+r,g+x,o+r,o+x "${path}" #>/dev/null 2>&1 # install path and sub path
    fi
    return 0
}

:<<!
* @description: Ensure has permission to create user and group
* @return: void
!
unset_user_creation_immutable() {
    immutable_status=()
    local PATHS=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow")
    for (( i=0; i<${#PATHS[@]}; i++)) ; do
	is_immutable "${PATHS[i]}"
        if [[ $? -eq 0 ]] ;then
          immutable_status[i]=yes
          chattr -i "${PATHS[i]}"
        else
          immutable_status[i]=no
        fi
    done
    return 0  
}

:<<!
* @description: Recover immutable settings
* @return: void
!
set_user_creation_immutable() {
    local PATHS=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow")
    for (( i=0; i<${#immutable_status[@]}; i++)) ; do
	if [[ "${immutable_status[i]}" == "yes" ]]; then
          chattr +i "${PATHS[i]}" 
        fi
    done
    return 0 
}

trim_backreturn(){
	local str="$1"
	echo "${str%$'\r'}"
}

trim_both(){
	result=$(trim_leading "$1" "$2")
	trim_back "$result" "$2"
}

trim_string(){
	echo `echo "$1"|awk '{$1=$1};1'`
}

trim_back(){
	local str="$1"
	local trim="$2"
	if ((${#str} < ${#trim})); then
		echo $str
	fi

	if [ "${str: ((-${#trim}))}" == "${trim}" ]; then
		echo ${str:0:((${#str}-${#trim}))}
	else
		echo $str
	fi
}

trim_leading(){
	local str="$1"
	local trim="$2"
	if ((${#str} < ${#trim})); then
		echo $str
	fi

	if [ "${str:0:((${#trim}))}" == "${trim}" ]; then
		echo ${str:((${#trim}))}
	else
		echo $str
	fi
}

get_json_l1_val(){
	local conf="$1"
	local key="$2"
		
	local val=$(awk "/^\s*\"${key}\"\s*:/"'{print $2}' $conf)
	val=$(trim_string $val)
	val=$(trim_leading $val "\"")
	val=$(trim_back $val ",")
	val=$(trim_back $val "\"")
	echo "${val}"
}

set_json_l1_val(){
	local conf="$1"
	local key="$2"
	local val="$3"
	local strLine=`awk "/^\s*\"${key}\"\s*:/" $conf`
	sed -i "s@$strLine@  \"$key\": $val,@g" $conf
}

#array_check_append "${#dall[@]}" "${dall[@]}" "${#subs1[@]}" "${subs1[@]}"
array_check_append()
{
	local len=$1
	local i
	local all=()
	shift
	for i in $(seq 1 $len);
	do
		all=( "${all[@]}" "$1" )
		shift
	done

	len=$1
	local subs=()
	shift
	for i in $(seq 1 $len);
	do	
		subs=( "${subs[@]}" "$1" )
		shift
	done

	#------------------
	
	for subone in "${subs[@]}"
	do
		local found=0
		for allone in "${all[@]}"
		do
			if [[ "${allone}" = "${subone}" ]]; then
				found=1
			fi
		done
		
		if [ $found -eq 0 ]; then
			all=( "${all[@]}" "${subone}" )
		fi
	done
	echo "${all[@]}"
}

is_valid_yes() {
    local MARKS=("yes" "y")
    local value=$(toLowerCase "$1")
    is_in_array "${value}" "${MARKS[@]}"
    if [ $? -ne 0 ]; then 
		return 1
    fi
	return 0
}

is_valid_no() {
    local MARKS=("no" "n")
    local value=$(toLowerCase "$1")
    is_in_array "${value}" "${MARKS[@]}"
    if [ $? -ne 0 ]; then 
		return 1
    fi
	return 0
}

replaceval() {
    local search="$1"
    local replace="$2"
	local file="$3"
    # Note the double quotes
    sed -i "s/${search}/${replace}/g" "${file}"
}

append_folder_name() {
	local nbpath="$1"
	local folder="$2"
	if [[ $nbpath = *$folder ]]; then
		echo $nbpath		
	elif [[ $nbpath = *$folder/ ]]; then
		nbpath="${nbpath:0:${#nbpath}-1}"
		echo $nbpath
	elif [[ $nbpath = */ ]]; then
		nbpath="${nbpath}$folder"
		echo $nbpath
	else
		nbpath="${nbpath}/$folder"
		echo $nbpath
	fi	
    #return 0	
}

<<!
* @description: Extract and initialize SSV
* @param return_code
* @return: 0|1
!
begin_init_ssv() {
	if ! tar xf ./sources/ssv.tar.gz -C ./sources/; then
        set_last_error "Failed to extract ssv.tar.gz."
        return 1
    fi

	if ! "./sources/ssv/NBInitSSV"; then
        set_last_error "Failed to initialize ssv."
        return 1
    fi	

	return 0
}

<<!
* @description: Extract and initialize SSV
* @param return_code
* @return: 0
!
end_init_ssv() {
	local ssvpath="./sources/ssv"
	rm -rf "${ssvpath}"
	return 0
}

<<!
* @description: initialize SSV
* @param return_code
* @return: 0|1
!
init_ssv() {
	begin_init_ssv
	local ret=$?
    if [ $? -ne 1 ]; then
        end_init_ssv
    fi

	return $ret
}

<<!
* @description: encrypt SSV
* @param return_code
* @return: 0|1
!
enc_ssv() {
	local encVal=$("./sources/ssv/NBInitSSV" -enc "$1")
	echo $encVal
	if [ -z "${encVal}" ]; then
		set_last_error "Encrypted password is empty."
		return 1
	fi
	return 0
}


<<!
* @description: encrypt SSV
* @param return_code
* @return: 0|1
!
enc_ssv_all() {
    local dummy=$(begin_init_ssv)
	local ret0=$?
	if [ $ret0 -ne 0 ]; then
		echo ""
		if [ $ret0 -ne 1 ]; then
			dummy=$(end_init_ssv)
		fi
		return 1
    fi   
  
	enc_ssv "$1"
	local ret1=$?

    dummy=$(end_init_ssv)
		
	return $ret1
}

<<!
* @description: change context
* @param path
* @return: 0|1
!
change_context() {
	local path=$1

	if (! getenforce | grep "Disabled" >/dev/null 2>&1 ); then
		chcon system_u:object_r:usr_t:s0 -R "${path}"
		if [ $? -ne 0 ]; then
			set_last_error "Failed to change context for the path of ${path}."
			return 1
		fi   
	fi

	return 0
}
