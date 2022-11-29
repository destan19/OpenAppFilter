#!/bin/sh
CLASS_NAME_FILE="/tmp/app_class.txt"
f_file=$1
cur_class=""
cur_class_file=""
test -z "$f_file" && return
test -d /tmp/appfilter && rm /tmp/appfilter -fr

mkdir /tmp/appfilter
rm $CLASS_NAME_FILE
while read line
do
    echo "$line"| grep "^#class"
    if [ $? -eq 0 ];then
        class=`echo $line| grep '#class' | awk '{print $2}'`
	if ! test -z "$class";then
		cur_class=$class
		cur_class_file="/tmp/appfilter/${cur_class}.class"
		if [ -e "$cur_class_file" ];then
			rm $cur_class_file 
		fi
		touch $cur_class_file
		echo $line |  awk '{print $3 " " $2 " "$4}' >>$CLASS_NAME_FILE
	fi
	continue
    fi
    test -z "$cur_class" && continue
    appid=`echo "$line" |awk '{print $1}'`
    appname=`echo "$line" | awk '{print $2}' | awk -F: '{print $1}'`
    echo "$appid $appname" >> $cur_class_file
done  < $f_file
