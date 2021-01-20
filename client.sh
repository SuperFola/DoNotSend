#!/usr/bin/env bash

if [[ $# != 2 ]]; then
    echo "Usage:"
    echo "      $0 hostname message"
    exit 1
fi

StartDate=`date -u +"%s.%N"`

# create message, remove padding
stripped_b32=`echo $2 | base32 | tr -d =`
# create domain
crafted_domain="${stripped_b32}.$1"
# make the DNS query and retrieve the answers
answer=`dig $crafted_domain TXT`
# decode answer
message=`echo $answer | grep -A 1 ";; ANSWER SECTION:" | tail -n 1 | egrep -o "\".+\"" | cut -c 2- | rev | cut -c 2- | rev`
length=$((4 - $(expr length "$message") % 4))
# add padding back accordingly
case "$length" in
"1")
    message="${message}="
    ;;
"2")
    message="${message}=="
    ;;
"3")
    message="${message}==="
    ;;
*)
    ;;
esac
# decode
decoded=`echo $message | base64 -d`

FinalDate=`date -u +"%s.%N"`
elapsed=`date -u -d "0 $FinalDate sec - $StartDate sec" +"%S.%N"`
echo "Received in $elapsed seconds"
echo $decoded