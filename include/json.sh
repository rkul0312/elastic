#!/bin/bash

############################################################
# @param $1: The json file to get the value of a key       #
# @param $2: The key                                       #
# @echo: The value of the key. If the key does not exist,  #
#        the value will be empty.                          #
############################################################
get_json_key_value() {
	local json=$1
	local key=$2
	local value=$(cat "${json}" | "$(dirname "${BASH_SOURCE[0]}")/jq" ".${key}" )

	echo ${value}
}

set_json_key_value() {
	local json=$1
	local key=$2
	local value=$3
	local result=$("$(dirname "${BASH_SOURCE[0]}")/jq" ".${key}=\"${value}\"" "${json}")
	
	echo "${result}" > "${json}"
	echo $?
}