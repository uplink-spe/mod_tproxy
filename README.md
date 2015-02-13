Uplink SPE tproxy plugin module
===============================

This module is a live example of a plugin module running with Uplunk Subscriber Policy Engine (Uplink SPE). 
Uplink SPE (<http://uplink-spe.com>) is an implementation of software BRAS (Broadband Remote Access Server), working as a Linux kernel module.
While Uplink SPE is a proprietary solution, this plugin comes as GPL-licenced to allow anyone extend actions/matches/NAT.


Installation
------------

Before compiling this module, you need to :
1. obtain a USPE.Module.symvers file from your Uplink SPE distribution. Make sure you have same Uplink SPE version AND Linux kernel version.
2. copy obtained USPE.Module.symvers into mod_tproxy folder
3. run `./configure` to create Makefile
4. run `make` to build plugin kernel module
5. run `make install` to install kernel module
6. run `depmod -a`
7. now you can load module using `modprobe 

Also, to make this plugin work with uspe-client tool, you would need to compile user-space libs, located in lib directory.
1. Change into directory ./lib
2. run `autoreconf -i`
3. run `./configure`
4. run `make`
5. run `make install`
6. done!

