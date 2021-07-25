#!/bin/bash

num=16
port=8080
cmd=$1
for i in $(seq 0 $num)
do
        $cmd $port&
        ((port+=1))
done
