=============================
TOOLs installation and usage:
=============================

Installation:
-------------

This tools require several dependencies, besides those of osmocom.
There is a list of dependencies used in ubuntu, if you are using
another distro it shouldn't be hard to find equivalents, because they are all
python dependencies, so you can use easy_install or pip.

    apt-get install pcscd python-mechanize python-jinja2 python-pyscard 
    python-lxml python-serial

Ubuntu preparation guide:
-------------------------

Install git.

    sudo apt-get install git

Add support for reading serial devices and disks as non superuser:

    sudo usermod -a -G dialout <your_username>
    sudo usermod -a -G disk <your_username>

Install wireshark and add support for running it as user:

    sudo apt-get install wireshark
    sudo apt-get install libcap2-bin
    sudo groupadd wireshark
    sudo usermod -a -G wireshark <your_username>
    newgrp wireshark
    sudo chgrp wireshark /usr/bin/dumpcap
    sudo chmod 750 /usr/bin/dumpcap
    sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

Install osmocom deps:
   
   sudo apt-get install libtool shtool autoconf git-core pkg-config make gcc

Install arm toolchain:

    sudo apt-get install python-software-properties
    sudo add-apt-repository ppa:bdrung/bsprak
    sudo apt-get update
    sudo apt-get install arm-elf-toolchain

If you have precise(12.04) you will have to change from precise to oneiric in "/etc/apt/sources.list.d/bdrung-bsprak-precise.list".

Install deps for gsmcrack.py:

    apt-get install pcscd python-mechanize python-jinja2 python-pyscard 
    python-lxml python-serial

Install sniffer:

    git clone https://github.com/offlinehacker/osmocom-bb.git
    cd osmocom-bb/src
    make

Install spoofer:

    git clone https://github.com/offlinehacker/osmocom-bb.git osmocom-bb-identity
    cd osmocom-bb-identity
    git checkout identity
    cd src
    make

You are ready to go...

Usage:
------
