A Very high performance rsync-like tool for Swift
=================================================
[![Build Status](https://api.travis-ci.org/pierresouchay/swiftsync.svg)](https://travis-ci.org/pierresouchay/swiftsync)

Swift Sync is a tool to synchronize your Swift Repositories with your filesystem.

It currently only supports Swift to local filesystem (but support to upload will eventually be added)

It focuses on high performance, so is highly multithreaded, for instance with good latency, connections,
and local disk performance (SSD), it can analyze differences in trees of more than 10GB of dozen of thousands of
files in less than 10 seconds.

Usage and Configuration
=======================

Requirements
------------

Install golang (All Operating systems)

Install
-------

```sh
go get github.com/pierresouchay/swiftsync
```

Getting Started
---------

Launchedl without any argument, it will create a default configuration file. If you loaded a openstack.rc
file, it will generate the configuration using those values, example:
```json
{
    "keystone": {
        "url": "https://identity.fr1.cloudwatt.com/v2.0/tokens",
        "post": {
            "auth": {
                "passwordCredentials": {
                    "username": "me@example.com",
                    "password": "password is missing"
                },
                "tenantName": "tenantName, or you can use tenantId property instead"
            }
        },
        "region": "",
        "usePublicURL": true
    },
    "target": {
        "containers": [
            ".*"
        ],
        "directory": "sync",
        "ignore": [],
        "strictMd5": false,
        "overwriteLocalChanges": false
    }
}
```

Comments about the options
--------------------------

* url: the identity URL (Keystone)
* region: by default, it will use the first region given by keystone. Setting tis value let you choose a particular region

* containers: a list of regexps to apply to the containers names. If none match, container will not be synchronized
* directory: the target directory where to put all the synchronized containers (relative to execution path or absolute)
* ignore: a list of regexp patterns to apply to ignore some files from Cloud
* strictMd5: if set to true, will always ensure local MD5 is the same as the file on server. Otherwise, use heursistics to guess when it MD5 must be computed


When launched with the configuration path, it will sync.

Other
=====
Source code is provided as it is, it has been tested only with Cloudwatt's Swift, but I'll be
happy to help fixing code if it does not work with your favourite Cloud provider.

Code has not been tested under Microsoft Windows, but I'll be happy to provide fixes if you find some bugs (path related bugs probably)

This is my first golang project, written in 2 days without prior Golang knowledge. Feel free to fix wrong assumptions I made and send pull requests!

Static Binaries
===============
Binaries are provided here: [https://github.com/pierresouchay/swiftsync/releases](https://github.com/pierresouchay/swiftsync/releases) each time a tag is created.

You can build your own binaries by yourself by issuing the command:
```shell
go build -o swift2fs main.go
```

Performance Sample and Output
=============================

26Gb of data in more than 31k files in 41 containers, less than 2 seconds to synchronize the full filesystem in a tiny Ubuntu VM @Cloudwatt!

```
$ time ./swift2fs-linux-amd64 conf.json
 Sync Status   Downloaded      in Sync      Skipped       Errors  Total Files        Bytes     DL Bytes Name
          OK            0            0            0            0            0            0            0 CLOUDWATTBOX
          OK            0           32            0            0           32    132227121            0 conteneur with spaces
          OK            0           24            0            0           24   6797461095            0 globi
          OK            0           29            0            0           29    118019074            0 coin
          OK            0            2            0            0            2      4534294            0 download
          OK            0            0            0            0            0            0            0 hého$
          OK            0           28            0            0           28     25813532            0 12
          OK            0          133            0            0          133   6921452094            0 downloads
          OK            0            4            0            0            4     12482574            0 hop
          OK            0            1            0            0            1      2555363            0 canard2
          OK            0            2            0            0            2      3716526            0 ContainerwithVersions
          OK            0            2            0            0            2     24008235            0 fbureau
          OK            0            1            0            0            1         9726            0 heat-stacks
          OK            0           73            0            0           73    485136008            0 bapteme_joseph
          OK            0            4            0            0            4       682791            0 iaas
          OK            0            1            0            0            1         8006            0 UnicodeTest_日本語_™ لوحة المفاتيح العرب
          OK            0           25            0            0           25     95868574            0 media
          OK            0            9            0            0            9      1853696            0 helloWorld
          OK            0            2            0            0            2      1032430            0 partage-jean-brice
          OK            0           46            0            0           46    335740019            0 photos_backup
          OK            0            0            0            0            0            0            0 testDossiers
          OK            0            3            0            0            3      1419335            0 mySharedContainerWithUserGuest
          OK            0           10            0            0           10      1815279            0 plop
          OK            0            5            0            0            5      1354538            0 pubWeb
          OK            0          512            0            0          512    114746394            0 backups
          OK            0          514            0            0          514   1456288247            0 books
          OK            0           11            0            0           11     54021585            0 web
          OK            0            9            0            0            9   2705271389            0 videos
          OK            0          129            0            0          129    182687948            0 share
          OK            0          372            0            0          372    367981164            0 hého € !
          OK            0           10            0            0           10    119231012            0 work
          OK            0          451            0            0          451    769844547            0 photos
          OK            0          877            0            0          877    441268171            0 origami2
          OK            0         1281            0            0         1281    150708382            0 NewContainer
          OK            0         1564            0            0         1564    130652667            0 NouveauConteneur
          OK            0         2158            0            0         2158    160441828            0 11
          OK            0         2035            0            0         2035   1447298530            0 origami
          OK            0         2095            0            0         2095   2711636515            0 monStockage
          OK            0         2382            0            0         2382    821573274            0 pop
          OK            0         5013            0            0         5013     27313711            0 versions
          OK            0        12000            0            0        12000        60894            0 many

real	0m1.103s
user	0m0.629s
sys	0m0.126s
```

