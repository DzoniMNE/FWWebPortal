#!/bin/sh
python3 -m pylint --output-format=parseable \
	--disable=C0103,C0114,C0115,C0116 \
	--disable=C0301,C0330 \
	--disable=R0801 \
	--disable=R0903,R0912,R0913,R0914,R0915 \
	--disable=R1705,R1716 \
	--disable=W0613 \
	"tuitfw"
