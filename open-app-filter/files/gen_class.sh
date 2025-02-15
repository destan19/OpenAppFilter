#!/bin/sh
CLASS_NAME_FILE="/tmp/app_class.txt"
f_file=$1
test -z "$f_file" && return

test -f $CLASS_NAME_FILE &&{
	rm $CLASS_NAME_FILE
}
cat $f_file  |grep "#class" | awk '{print $3 " " $2 " " $4}' >$CLASS_NAME_FILE

