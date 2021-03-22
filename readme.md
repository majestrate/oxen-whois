# loki-whois

A whois server for lns


## building

requirements:

* oxenmq
* libsodium 1.0.18
* nlohmann-json 3.x
* cmake

build:

    $ git submodule update --init --recursive
    $ mkdir build 
    $ cd build
    $ cmake ..
    $ make
    
## running

set to run with systemd:

    $ sudo make install
    $ sudo cp contrib/loki-whois.service /etc/systemd/system/
    $ sudo systemctl enable --now loki-whois
    
    
## usage

query the server explicitly using the `whois` tool:

    $ whois -h localhost.loki jeff.loki
    

