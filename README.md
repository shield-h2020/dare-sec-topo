# CyberSecurity Topologies v1.0

Welcome to the DARE's CyberSecurity Topologies tool page.

## Content

This project includes a Python module, named `cybertop`, and a sample application that can be run as a daemon.

```
.
├── cybertop
├── daemon
├── docs
├── LICENSE
├── makefile
├── MANIFEST.in
├── README.md
├── setup.py
└── tests
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

A Python 3 environment is required to run the project. To create it, just run:

```
$ virtualenv -p python3 /path/to/venv
```

To activate it, just run:

```
$ source /path/to/venv/bin/activate
```

Dependencies are listed here for simplicity:

- `setuptools`;
- `pyinotify`;
- `yapsy`;
- `lxml`;
- `python-dateutil`;
- `pika`.

You can install them by issuing the following command:

```
$ pip install -r requirements.txt
```

## Installation

You can install the `cybertop` module by issuing the following command (in the
virtualenv):

```
$ python setup.py install
```

The built-in test suite can be run by issuing the following command (in the
virtualenv):

```
$ python setup.py test
```

## Usage

The main class that you should use is `cybertop.CyberTop`.
It will read the configuration from a file named `cybertop.cfg` (you can look at an example in the `tests` directory).
It has a method called `getMSPLs()` that receives in input the path of a DARE CSV attack file and will return the XMLs of the HSPLs and MSPLS.

## Configuration

### Logging
Each operation is logged into a file named `cybertop.log`. You can configure the logging by specifying a `logging.ini` file with proper handlers (an example file is in the `tests` directory).

### App Configuration

Application config is under `cybertop.cfg` file. Find a reference example of the
file in the `tests` directory. This file includes entries to configure the
following elements:

* Directory for local CSV read (which can be disabled)
* Parameters for the DARE queue, which is read by our module
* Parameters for the Dashboard queue, which is written by our module
* Output files to pretty-print HSPLs and MSPLs (for testing)
* HSPL optimisation parameters (merging options)
* Rate limiting specific directives (which are systemwide used
  by the engine)


## (Preferred) Systemd service

The preferred way of using the component is to install it as `systemd` service by running the `daemon/cybertop_systemd_install.sh` script. **N.B:** the Python interpreter accessed by the root user must have the `cybertop` package installed. You **MUST** explicitely configure the Python shebang in `cybertop_systemd_install.sh` to match the path of your Virtualenv.

When you install cybertop as systemd service, it will perform the following
operations:

1. Create a binary named `/usr/local/bin/cybertop-daemon`
2. Create a default systemd configuration file in `/etc/default/cybertop`, that
you **MUST** edit with the following data:

```
CYBERTOP_CONF="/path/to/cybertop.cfg"
CYBERTOP_LOG_CONF="/path/to/logging.ini"
```

3. Copy the systemd service entry in the proper directroy and enable the service

Before running it, you should ensure that `cybertop.cfg` and `logging.ini` are
properly configured (refer to the previous section for details).

## Standalone daemon

You can also use the tool as a daemon using the `daemon/daemon.py` script. It will listen when a file is created into a directory and react accordingly, sending the results to the dashboard.

The daemon app can be run in standalone mode as follows:

```
python daemon.py -c /path/to/cybertop.cfg -l /path/to/logging.ini
```
