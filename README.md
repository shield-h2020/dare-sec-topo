# CyberSecurity Topologies v0.1 #

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

## Usage ##

The main class that you should use is `cybertop.CyberTop`.
It will read the configuration from a file named `cybertop.cfg` (you can look at an example in the `test` directory).
It has a method called `getMSPLs()` that receives in input the path of a DARE CSV attack file and will return the XMLs of the HSPLs and MSPLS.

Each operation is logged into a file named `cybertop.log`.
