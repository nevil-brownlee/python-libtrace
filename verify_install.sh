#!/bin/sh

# Copyright (C) 2015 by Habib Naderi, U Auckland

export TZ=Pacific/Auckland

if [ "$1" -eq 2 ] || [ "$1" -eq 3 ]; then
	echo verifying installation for python $1 ...
	cd test
	python$1 run_test.py -d v$1-test-cases/ -t > /tmp/tr
	ret=$?
	if [ "$ret"  -ne  0 ]; then
		echo "verification failed."
	else
		n=`cat /tmp/tr | grep "py:" | grep "Failed" | wc -l`
		if [ "$n" -gt 0 ]; then
			echo $n "test(s) failed."
		else
			echo "installation complete."
		fi
	fi
	cd ..
else
	echo "verification failed for python version "$1"."
fi




