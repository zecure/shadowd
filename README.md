[![Build Status](https://travis-ci.org/zecure/shadowd.svg)](https://travis-ci.org/zecure/shadowd)
![Logo](http://shadowd.zecure.org/img/logo_small.png)

**Shadow Daemon** is a collection of tools to **detect**, **record** and **prevent** **attacks** on *web applications*.
Technically speaking, Shadow Daemon is a **web application firewall** that intercepts requests and filters out malicious parameters.
It is a modular system that separates web application, analysis and interface to increase security, flexibility and expandability.

This is the main component that handles the analysis and storage of requests.

# Documentation
For the full documentation please refer to [shadowd.zecure.org](https://shadowd.zecure.org/).

# Installation
## Preparation
Use cmake to configure and prepare the project. It is a good idea to create a separate directory for this.
A typical installation might look like this:

    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE=Release ..

## Compilation
If cmake is successful it creates a makefile. Use it to compile and install the project:

    make shadowd
    make install

## Database
Install and configure a database server. At the moment shadowd officially supports PostgreSQL and MySQL.
If you are done create a new user and database and import the correct layout, e.g.:

    psql -Ushadowd shadowd < /usr/share/shadowd/pgsql_layout.sql
    mysql -ushadowd -p shadowd < /usr/share/shadowd/mysql_layout.sql

# Configuration
The installer copies the configuration file to */etc/shadowd/shadowd.ini*. The file is annotated and should be self-explanatory.
