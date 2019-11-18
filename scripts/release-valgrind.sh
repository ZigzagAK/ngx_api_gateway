#!/bin/bash

ulimit -c unlimited
ulimit -s 16384
DIR=$(pwd)
export LD_LIBRARY_PATH=$DIR/lib:$LD_LIBRARY_PATH:$ORACLE_HOME:$ORACLE_HOME/lib
export DYLD_LIBRARY_PATH=$DIR/lib:$DYLD_LIBRARY_PATH:$ORACLE_HOME:$ORACLE_HOME/lib
valgrind --trace-children=yes --tool=memcheck --log-file=debug.log ./sbin/nginx -p $DIR
