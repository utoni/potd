[![Build Status](https://travis-ci.org/lnslbrty/potd.svg?branch=master)](https://travis-ci.org/lnslbrty/potd)
[![Coverity Status](https://scan.coverity.com/projects/16232/badge.svg?flat=1)](https://scan.coverity.com/projects/16232)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/8ee6023b774f4f31b58f13aeb28a4bc1)](https://www.codacy.com/app/lnslbrty/potd?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=lnslbrty/potd&amp;utm_campaign=Badge_Grade)
[![GitHub issues](https://img.shields.io/github/issues/lnslbrty/potd.svg)](https://github.com/lnslbrty/potd/issues)
[![GitHub license](https://img.shields.io/github/license/lnslbrty/potd.svg)](https://github.com/lnslbrty/potd/blob/master/COPYING)
[![Gitter chat](https://badges.gitter.im/honeypotdaemon/Lobby.png)](https://gitter.im/honeypotdaemon/Lobby)

# honey[potd]aemon

This project is part of a BA thesis. It is currently in a pre-alpha state.

## Dependencies

Kernel/libc requirements: Cgroups, Namespaces (UTS, IPC, PID, NET, CGROUPS)

Required: libssh, pthread

Optional: libseccomp

A chroot'able directory that contains an executable named '/bin/sh'.

## HowTo

Build:
  - `./autogen.sh`
  - `./configure`
  - `make`

Run:
  - `./src/potd --redirect 0.0.0.0:2222:127.0.0.1:22222 
                --protocol 127.0.0.1:22222:127.0.0.1:33333 
                --jail 127.0.0.1:33333`

    This will process, filter and redirect all traffic incoming from 0.0.0.0:2222 to the
    protocol handler at 127.0.0.1:22222 and if the protocol accepts it, it will forward
    all traffic to the jail/sandbox at 127.0.0.1:33333.
    
    (clunky atm, will be simplified in the future)
  - see `./src/potd --help`

## Features

The ssh server currently supports only shell channels. But exec and direct-tcp channels are coming soon!

Supported protocols (at the moment):
  - ssh with libssh

Protocols to implement:
  - HTTP
  - ssh with openssh
  - SCADA
  - MySQL

Suits perfect for your favoured Desktop/Server/OpenWrt Linux system.

## TODOs

- RESTful listener for output sampled data from different processes
    (send (real-time)statistics about protocols/jails/etc to higher level apps)
- ptrace support for jailed processes (trace syscalls)
- improved event handling (maybe libevent?)
