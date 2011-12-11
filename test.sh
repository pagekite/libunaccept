#!/bin/bash
export UNACCEPT_RULES=rules.txt
export UNACCEPT_BLOCKING=1
export UNACCEPT_MAX_RULES=4
export UNACCEPT_TARPIT_SIZE=100000
export LD_PRELOAD=./libunaccept.so
exec nc -v -l -p 12020
