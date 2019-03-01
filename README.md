[![Build Status](https://travis-ci.org/bitcoinj-sv/bitcoinj-sv.png)](https://travis-ci.org/bitcoinj-sv/bitcoinj-sv)   [![Coverage Status](https://coveralls.io/repos/github/bitcoinj-cash/bitcoinj/badge.svg?branch=cash-0.14)](https://coveralls.io/github/bitcoinj-cash/bitcoinj?branch=cash-0.14) [![Javadocs](http://www.javadoc.io/badge/cash.bitcoinj/bitcoinj-core.svg)](http://www.javadoc.io/doc/cash.bitcoinj/bitcoinj-core) 

### NOTICE
The bitcoinj-sv library will be undergoing major changes for version 1.0.0. This version, 0.9.0, has been released 
with minor changes as a temporary measure.

### Welcome to bitcoinj-sv

The bitcoinj-sv library is a Java implementation of the Bitcoin SV protocol. This library is a fork of Mike Hearn's original bitcoinj library aimed at supporting Bitcoin SV.

It allows maintaining a wallet and sending/receiving transactions without needing a full blockchain node.

### Technologies

* Java 8 
* [Maven 3+](http://maven.apache.org) - for building the project
* [Google Protocol Buffers](https://github.com/google/protobuf) - for use with serialization and hardware communications

### Getting started

To get started, it is best to have the latest JDK and Maven installed. The HEAD of the `master` branch contains the latest release and the `dev` branch contains development code.

#### Building from the command line

To perform a full build use
```
mvn clean package
```
The outputs are under the `target` directory.

#### Building from an IDE

Alternatively, just import the project using your IDE. [IntelliJ](http://www.jetbrains.com/idea/download/) has Maven integration built-in and has a free Community Edition. Simply use `File | Import Project` and locate the `pom.xml` in the root of the cloned project source tree.

### Example applications

These are found in the `examples` module.

### Contributing to bitcoinj-sv

Contributions to bitcoinj-sv are welcome and encouraged.

* the development branch is `dev` 
* Travis-CI is [here](https://travis-ci.org/bitcoinj-sv/bitcoinj-sv)
* Coveralls test coverage report is [here](https://coveralls.io/github/bitcoinj-sv/bitcoinj-sv)
