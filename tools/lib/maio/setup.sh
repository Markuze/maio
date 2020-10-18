#!/bin/bash

echo "setup hugepages"

sudo sh -c "echo 256 > /proc/sys/vm/nr_hugepages"
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs none /mnt/huge

echo "gcc -Wall hugepage-mmap.c -o hugepage-mmap"
