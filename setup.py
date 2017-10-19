from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='cybertop',

    version='1.0',

    description='Cybersecurity Topologies module (SHIELD)',
    long_description=long_description,

    url='https://github.com/shield-h2020/dare-sec-topo',

    author='TORSEC - Politecnico di Torino',
    author_email='security@polito.it',

    license='Apache License 2.0',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache License 2.0',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],

    keywords='sample setuptools development',

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    install_requires=[
        'setuptools',
        'pyinotify',
        'yapsy',
        'lxml',
        'python-dateutil',
        'pika'
    ],

    extras_require={
        'dev': ['check-manifest'],
        'test': ['coverage'],
    },
    test_suite="tests",
    include_package_data = True,
    zip_safe = False,
)
