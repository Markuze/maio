#!/bin/bash

HUGE_PATH=/'mnt/huge'
echo "setup hugepages"

sudo sh -c "echo 2048 > /proc/sys/vm/nr_hugepages"
mkdir -p $HUGE_PATH
sudo mount -t hugetlbfs none $HUGE_PATH

#echo "gcc -Wall hugepage-mmap.c -o hugepage-mmap"
#sudo sh -c "echo 1 > /proc/sys/kernel/ftrace_dump_on_oops"
#rm -f hugepage-mmap
cat /proc/meminfo
#gcc -Wall hugepage-mmap.c -o hugepage-mmap
#sudo ./hugepage-mmap
