./setup.sh
make
sudo sysctl kernel.ftrace_dump_on_oops=1
sudo sysctl kernel.panic=0
sudo ./maio_tcp_tx_client
