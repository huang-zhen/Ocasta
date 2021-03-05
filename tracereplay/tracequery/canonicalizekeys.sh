#!/bin/bash
# canonicalizekeys.sh

canonicalize() {
	FILE=$1
	OUTFILE=$2
	grep "VERSION_NUM" $FILE
	if [ $? -eq 0 ]; then
		echo "VERSION_NUM" already used in $FILE
		return 1
	fi
	grep "USER_NAME" $FILE
	if [ $? -eq 0 ]; then
		echo "USER_NAME" already used in $FILE
		return 1
	fi
	sed 's/11\.0/VERSION_NUM/' $FILE > $FILE.1
	sed 's/12\.0/VERSION_NUM/' $FILE.1 > $FILE.2
	sed 's/14\.0/VERSION_NUM/' $FILE.2 > $FILE.3
	sed s/S-1-5-21-2886906930-2409376716-3799711308-1000/USER_NAME/ $FILE.3 > $FILE.4
	sed s/S-1-5-21-2325353835-4259467031-4104352378-1008/USER_NAME/ $FILE.4 > $FILE.5
	sed s/S-1-5-21-2370212508-2774756865-78130-1000/USER_NAME/ $FILE.5 > $FILE.6
	sed s/S-1-5-21-1078081533-651377827-839522115-1003/USER_NAME/ $FILE.6 > $FILE.7
	sed s/S-1-5-21-1121259772-4041853746-1074902948-1000/USER_NAME/ $FILE.7 > $FILE.8
	mv $FILE.8 $OUTFILE
	#diff $FILE $OUTFILE
	return 0
}

for file in *\.clusters
do
	canonicalize $file $file.can
done


