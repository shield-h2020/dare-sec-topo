from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='cybertop',

    version='0.2',

    description='Cybersecurity Topologies module (SHIELD)',
    long_description=long_description,

    url='https://github.com/shield-h2020/dare-sec-topo',

    author='TORSEC - Politecnico di Torino',
    author_email='security@polito.it',

    license='Apache License 2.0',

    classifiers=[
        'Development Status :: 3 - Alpha',

        'License :: OSI Approved :: Apache License 2.0',

        #'Programming Language :: Python :: 2',
        #'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],

    keywords='sample setuptools development',

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    install_requires=['pyinotify','yapsy','lxml','python-dateutil','pika'],

    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        'dev': ['check-manifest'],
        'test': ['coverage'],
    },

    # If there are data files included in your packages that need to be
    # installed, specify them here.  If using Python 2.6 or less, then these
    # have to be included in MANIFEST.in as well.
    package_data={
        'cybertop': ['xsd/*.xsd','plugins/*.yapsy-plugin','recipes/*.xml'],
    },

    # Although 'package_data' is the preferred approach, in some case you may
    # need to place data files outside of your packages. See:
    # http://docs.python.osrg/3.4/distutils/setupscript.html#installing-additional-files # noqa
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    #data_files=[('my_data', ['data/data_file'])],

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    #entry_points={
    #    'console_scripts': [
    #        'sample=sample:main',
    #    ],
    #},
)
