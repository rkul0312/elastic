#!/bin/bash

# Notes: cannot parse abc:http://www.xxx.com 
#################################################
# https://github.com/ash-shell/yaml-parse
# This function will Parse a simple YAML file
# and will output bash variables
#
# Typical Usage:
# eval $(parse_yaml sample.yml "PREFIX_")
#
# @param $1: The yaml file to parse
# @param $2: The prefix to append to all of the
#       variables to be created
#################################################
function parse_yaml() {
    local yaml_file=$1
    local prefix=$2
    local s
    local w
    local fs

    s='[[:space:]]*'
    w='[a-zA-Z0-9_.-]*'
    fs="$(echo @|tr @ '\034')"

    sed -e "/- [^\"][^\'].*:/s|\([ ]*\)- \($s\)|\1-\n  \1\2|g" "$yaml_file" |

    sed -ne '/^--/s|--||g; s|\"|\\\"|g; s/\s*$//g;' \
        -e "/#.*[\"\']/!s| #.*||g; /^#/s|#.*||g;" \
        -e "s|^\($s\)\($w\)$s:$s\"\(.*\)\"$s\$|\1$fs\2$fs\3|p" \
        -e "s|^\($s\)\($w\)$s[:-]$s\(.*\)$s\$|\1$fs\2$fs\3|p" |

    awk -F"$fs" '{
        indent = length($1)/2;
        if (length($2) == 0) { conj[indent]="+";} else {conj[indent]="";}
        vname[indent] = $2;
        for (i in vname) {if (i > indent) {delete vname[i]}}
            if (length($3) > 0) {
                vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
                printf("%s%s%s%s=(\"%s\")\n", "'"$prefix"'",vn, $2, conj[indent-1],$3);
            }
        }' |
        
    sed -e 's/_=/+=/g' |
    
    awk 'BEGIN {
             FS="=";
             OFS="="
         }
         /(-|\.).*=/ {
             gsub("-|\\.", "_", $1)
         }
         { print }'
}

#################################################
# @param $1: The yaml file to check if there is
#       a key
# @param $2: The key to check if it exists
# @echo: $Ash__TRUE if the key exists,
#       $Ash__FALSE otherwise
#################################################
has_yaml_key() {
    local line=$(grep -x "^$2:.*" "$1")
    if [[ "$line" != "" ]]; then
        echo true
    else
        echo false
    fi
}