# loki-whois

A whois server for lns


## building

requirements:

* libuv 1.x
* lokimq 1.2
* cmake

build:

    $ mkdir build 
    $ cd build
    $ cmake ..
    $ make
    $ sudo make install
    
## running

set to run with systemd:

    $ sudo cp contrib/loki-whois.service /etc/systemd/system/
    $ sudo systemctl enable --now loki-whois
    
    
## usage

query the server explicitly using the `whois` tool:

    $ whois -h localhost.loki jeff.loki
    

