#Test tools

##Here you can find test tools for comparing MAIO with traditional TX methods (including zero-copy)

### Server
There is only one type of RX server, naive_server.c
First, change the port in the `naive-server.c`, if needed.
To build: `gcc naive_server.c -o naive_server`
Then just run the executable `./naive_server`

### Client test modes
- **naive:**  this is the simplest one, just uses `send()` function to send the data. Edit the `naive-client.c`
file and in the `main` make sure that `func()` is called. Change IP and port to match the `naive-server.c`.
  Build with `gcc naive_client.c -o naive_client` and observe the traffic.
  

- **sendfile:** this mode uses random 16K files that are populated in the TMPFS, along with `sendfile` function, which is zero-copy.

    Assuming current folder `/home/user`  and `K_FILES` set to 2000:

    Edit the `naive_client.cpp` file, set `K_FILES` to the desired number of files (the code sends them in the round robin fashion).
  - Set the `K_FILE_PATH` to '/home/user/files' 
  - Set IP and port to match the `naive_server.c` and in the `main` function comment the `func()` line but uncomment the `func1()` line.
    
  Then you need to create TMPFS and binary files.
  
  - `mkdir files`
  - `sudo mount -t tmpfs -o size=512m tmpfs files`
  - `cd files`
  - `for i in {0..1999}; do head -c 16K </dev/urandom >$i;done`
    
  Build `native_client.c` and run as in the `Naive` mode.


- **send() with zero-copy:** This mode is like `naive` but uses `MSG_ZEROCOPY` flag with `send()` function. 
    - Edit the `naive_client.cpp` file, set `K_MSGZEROCOPY` to 1, and make sure that in the `main()` function the `func()` is called.
    - Follow the `naive` mode instructions.