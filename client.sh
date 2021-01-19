#!/usr/bin/env bash

# send message
stripped_b32=`echo $1 | base32 | tr -d =`
crafted_domain="${stripped_b32}.dns.12f.pl"
answer=`dig @12f.pl $crafted_domain TXT`
# decode answer
message=`echo $answer | grep -A 1 ";; ANSWER SECTION:" | tail -n 1 | egrep -o "\".+\"" | cut -c 2- | rev | cut -c 2- | rev`
length=$((4 - $(expr length "$message") % 4))
# add padding accordingly
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

decoded=`echo $message | base64 -d`

echo "Received: $decoded"