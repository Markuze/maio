#!/bin/bash
function install {
         sudo make modules_install install 2>/dev/null;
         sudo update-grub2
         # sudo grub-reboot 0
}
time make -j `nproc` > /dev/null
[ $? -eq 0 ] && install;
