A Very high performance rsync-like tool for Swift
=================================================
[![Build Status](https://img.shields.io/travis/pierresouchay/swiftsync.svg)](https://travis-ci.org/pierresouchay/swiftsync)

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
Binaries are provided for convenience.

It is recommended to build it youselft using:
```shell
go build -o swift2fs main.go
```

* [Mac OS Build amd64](https://storage.fr1.cloudwatt.com/v1/AUTH_61b8fe6dfd0a4ce69f6622ea74444e0f/downloads/swift2fs-bin/swift2fs-linux-amd64?temp_url_sig=818fced6a0407d3426a41d39aeeeb62de931e43a&temp_url_expires=1465403760)
* [Linux Build amd64](https://storage.fr1.cloudwatt.com/v1/AUTH_61b8fe6dfd0a4ce69f6622ea74444e0f/downloads/swift2fs-bin/swift2fs-mac-amd64?temp_url_sig=f5c559838d4ba47635e06037a3ec60d59cf5c60c&temp_url_expires=1465403760)

