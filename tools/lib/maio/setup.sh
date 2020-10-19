#!/bin/bash

echo "setup hugepages"

sudo sh -c "echo 512 > /proc/sys/vm/nr_hugepages"
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs none /mnt/huge

echo "gcc -Wall hugepage-mmap.c -o hugepage-mmap"
gcc -Wall hugepage-mmap.c -o hugepage-mmap
sudo sh -c "echo 1 > /proc/sys/kernel/ftrace_dump_on_oops"
cat /proc/meminfo
