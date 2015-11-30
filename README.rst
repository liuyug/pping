PPING
=====

pping
    Protocal Ping

Support ICMP, HTTP, FTP etc. 

Requirement
===========

+ libcurl

Install
=======

::

    makedir build
    cd build
    cmake ../
    make

Run
====
::

    pping www.github.com
    pping http:\\www.github.com
    pping -c 1 - < test/mirrors
    pping --stat - < test/mirrors
