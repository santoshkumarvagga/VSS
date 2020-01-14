#!/bin/sh
setsid ./vsstrace.exe -f 0 +COORD +BUCOMP +WRITER +HWDIAG +IOCTL +GEN +indent -l 255 -o vsstrace.log &
sleep 2

