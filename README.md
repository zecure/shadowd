**Shadow Daemon** is a modular system that **detects and prevents known and unknown attacks against web applications**. It requires no source code changes, is very flexible and can be used for many different tasks, f.i. as *high-interaction honeypot* by security professionals to gather information about vulnerabilities, as *intrusion prevention system* by web administrators to protect internet sites or as *intrusion detection system* by network administrators to detect intruders.

# Documentation
This README is only a short guide to get you started quickly. For the complete user documentation please go to [https://shadowd.zecure.org/docs/current/](https://shadowd.zecure.org/docs/current/).

A programming reference can be found at [https://shadowd.zecure.org/references/current/](https://shadowd.zecure.org/references/current/) or you can create a new one with Doxygen.

# Demo
A demonstration of the Shadow Daemon web interface can be found at [https://demo.shadowd.zecure.org/](https://demo.shadowd.zecure.org/).

# Installation
## Build
Use cmake to configure and prepare the project. A typical installation might look like this:
```
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE=Release ..
make
make install
```

## Database
Install and configure a database server. At the moment shadowd officially supports PostgreSQL and MySQL, but inofficially many more are supported. If you are done create a new user and database and import the layout:
```
psql -Ushadowd shadowd < misc/databases/pgsql_layout.sql
mysql -ushadowd -p shadowd < misc/databases/mysql_layout.sql
```

## Configuration
Next you have to create a configuration file. You can base it on *misc/examples/shadowd.ini*. Now you should be able to start shadowd:
```
shadowd -c /etc/shadowd/shadowd.ini -V
```

# Usage
```
Shadow Daemon 0.1.0 -- High-Interaction Web Honeypot

Generic options:
  -h [ --help ]         produce help message
  -v [ --version ]      print version string
  -c [ --config ] arg   configuration file
  -V [ --verbose ]      show more debug output

Server options:
  -a [ --address ] arg (=127.0.0.1) bind to ip address
  -p [ --port ] arg (=9115)         bind to port
  -S [ --ssl ]                      activate ssl
  -C [ --ssl-cert ] arg             path to ssl cert
  -K [ --ssl-key ] arg              path to ssl key
  -H [ --ssl-dh ] arg               path to dhparam file
  -t [ --threads ] arg (=10)        sets the size of the threadpool

Daemon options:
  -D [ --daemonize ]    detach and become a daemon
  -L [ --log ] arg      file to store logs
  -P [ --pid ] arg      pid file
  -U [ --user ] arg     user to run daemon as
  -G [ --group ] arg    group to run daemon as
  -R [ --chroot ] arg   change root directory
```

## Example
```
shadowd -c /etc/shadowd/shadowd.ini -D -U swd -G swd -P /var/run/shadowd/shadowd.pid -L /var/log/shadowd/shadowd.log
```

Note that the pid and log path have to be absolute.

# Acknowledgments
- Network architecture vaguely based on the http_server3 example by Christopher M. Kohlhoff
- Blacklist rules based on PHPIDS by the phpids.org team
