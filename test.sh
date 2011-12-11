#!/bin/bash
export LIBUNACCEPT_RULES=config.d
export LIBUNACCEPT_BLOCKING=1
export LIBUNACCEPT_TARPIT_SIZE=100000
export LD_PRELOAD=./libunaccept.so
exec nc -v -l -p 12020
