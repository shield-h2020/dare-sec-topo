# CyberSecurity Topologies v0.4

Welcome to the DARE's CyberSecurity Topologies tool page.

## Content

This project includes a Python module, named `cybertop`, and a sample application that can be run as a daemon.

```
.
├── cybertop
│   ├── attacks.py
│   ├── cybertop.py
│   ├── hspl.py
│   ├── __init__.py
│   ├── log.py
│   ├── mspl.py
│   ├── parsing.py
│   ├── plugins
│   │   ├── ActionDrop.py
│   │   ├── ActionDrop.yapsy-plugin
│   │   ├── ActionLimit.py
│   │   ├── ActionLimit.yapsy-plugin
│   │   ├── FilterInputBytes.py
│   │   ├── FilterInputBytes.yapsy-plugin
│   │   ├── FilterInputPackets.py
│   │   ├── FilterInputPackets.yapsy-plugin
│   │   ├── FilterQueryDigits.py
│   │   ├── FilterQueryDigits.yapsy-plugin
│   │   ├── FilterQueryLength.py
│   │   ├── FilterQueryLength.yapsy-plugin
│   │   ├── ParserDNSTunneling.py
│   │   ├── ParserDNSTunneling.yapsy-plugin
│   │   ├── ParserDoS.py
│   │   ├── ParserDoS.yapsy-plugin
│   ├── plugins.py
│   ├── recipes
│   │   ├── DNS tunneling.xml
│   │   ├── DoS, high.xml
│   │   └── DoS, low.xml
│   ├── recipes.py
│   ├── util.py
│   └── xsd
│       ├── hspl.xsd
│       ├── landscape.xsd
│       ├── mspl.xsd
│       └── recipe.xsd
├── daemon
│   ├── cybertop_systemd_install.sh
│   ├── daemon.py
│   └── systemd
│       ├── cybertop
│       └── cybertop.service
├── LICENSE
├── Makefile
├── MANIFEST.in
├── README.md
├── setup.py
└── tests
    ├── __init__.py
    ├── cybertop.cfg
    ├── High-DNS tunneling-1.csv
    ├── High-DoS-1.csv
    ├── High-DoS-2.csv
    ├── High-DoS-3.csv
    ├── landscape1.xml
    ├── landscape2.xml
    ├── logging.ini
    ├── Low-DNS tunneling-1.csv
    ├── Low-DoS-1.csv
    ├── Low-DoS-2.csv
    ├── Low-DoS-3.csv
    ├── test_cybertop.py
    ├── Very high-DNS tunneling-1.csv
    ├── Very high-DoS-1.csv
    ├── Very high-DoS-2.csv
    ├── Very high-DoS-3.csv
    ├── Very low-DNS tunneling-1.csv
    ├── Very low-DoS-1.csv
    ├── Very low-DoS-2.csv
    └── Very low-DoS-3.csv
```

In particular:

- `cybertop` contains the main Python source files and package data of the project;
	- `plugins` contains the various plug-ins supported by the tool;
	- `recipes` contains the default recipes for the attack mitigation;
	- `xsd` contains the XSD schema files for the validations;
- `daemon` contains the sample app that uses the `cybertop` package and `systemd` integration;
- `tests` contains a set of unit tests and sample configuration files;
- `LICENSE` contains more information about the project license;
- `setup.py` is the `setuptools` file to install the `cybertop` package;
- `makefile` can be used to install or uninstall this tool;
- `MANIFEST.in` is the file that includes the paths of package data;
- `README.md` is the file that you are currently reading.

## Requirements

A Python 3 environment is required to run the project. Software dependencies can be installed by running the `setuptools` script.

Dependencies are also listed here for simplicity:

- `setuptools`;
- `pyinotify`;
- `yapsy`;
- `lxml`;
- `python-dateutil`;
- `pika`.

## Installation

You can install the `cybertop` module by issuing the following command:

```
$ python setup.py install
```

The built-in test suite can be run by issuing the following command:

```
$ python setup.py test
```

## Usage

The main class that you should use is `cybertop.CyberTop`.
It will read the configuration from a file named `cybertop.cfg` (you can look at an example in the `tests` directory).
It has a method called `getMSPLs()` that receives in input the path of a DARE CSV attack file and will return the XMLs of the HSPLs and MSPLS.

The module configuration resides in the `cybertop.cfg` file.

## Logging
Each operation is logged into a file named `cybertop.log`. You can configure the logging by specifying a `logging.ini` file with proper handlers (an example file is in the `tests` directory).

## Daemon app

You can also use the tool as a daemon using the `daemon/daemon.py` script. It will listen when a file is created into a directory and react accordingly, sending the results to the dashboard. 

The daemon app can be run in standalone mode as follows:

```
python daemon.py -c /path/to/cybertop.cfg -l /path/to/logging.ini
```

It can also be installed as `systemd` service by running the `daemon/cybertop_systemd_install.sh` script.

**N.B:** the Python interpreter accessed by the root user must have the `cybertop` package installed. You can explicitely configure the Python shebang in `cybertop_systemd_install.sh` to match the path of your Virtualenv.
The `cybertop.service` must be configured via the `/etc/default/cybertop` file, in which the paths for the `cybertop.cfg` and `logging.ini` file are defined.
