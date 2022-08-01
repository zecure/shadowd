![Logo](https://shadowd.zecure.org/img/logo_small.png)

[![Build Status](https://github.com/zecure/shadowd/actions/workflows/analyze.yml/badge.svg)](https://github.com/zecure/shadowd/actions/workflows/analyze.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=zecure_shadowd&metric=alert_status)](https://sonarcloud.io/dashboard?id=zecure_shadowd)

**Shadow Daemon** is a *web application firewall* that intercepts requests at application-level.
This repository contains the main component of Shadow Daemon that handles the analysis and storage of requests.

# Documentation
For the full documentation please refer to [shadowd.zecure.org](https://shadowd.zecure.org/).

# Installation
## Preparation
Use cmake to configure and prepare the project. It is a good idea to create a separate directory for this.
A typical installation might look like this.

    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE=Release ..

## Compilation
If cmake is successful it creates a makefile. Use it to compile and install the project.

    make shadowd
    make install

# Configuration
During the installation the configuration file is copied to */etc/shadowd/shadowd.ini*. The file is annotated and should be self-explanatory.
