# CyberSecurity Topologies v0.2 #

Welcome to the DARE's CyberSecurity Topologies tool.

## Content ##

This project consists of the following files/folders:
- `plugins` contains the MSPL refinement plug-ins;
- `src` contains the main Python source files of the project;
- `test` contains a set of unit tests;
- `recipes` contains the default recipes for the attack mitigation;
- `xsd` contains the XML schema files for the validations;
- `LICENSE` contains more information about the project license;
- `README.md` is the file that you are currently reading.

## Installation ##

You can install the `cybertop` module by executing:
```
$ python setup.py install
```

## Usage ##

The main class that you should use is `cybertop.CyberTop`.
It will read the configuration from a file named `cybertop.cfg` (you can look at an example in the `test` directory).
It has a method called `getMSPLs()` that receives in input the path of a DARE CSV attack file and will return the XMLs of the HSPLs and MSPLS.

Each operation is logged into a file named `cybertop.log`.

You can also use the tool as a daemon using the `daemon.py` script. It will listen when a file is created into a directory and reacts accordingly, sending the results to the dashboard. Everything is configurable through the usual configuration file `cybertop.cfg`.
