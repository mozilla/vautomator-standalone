#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("Readme.md", "r") as fh:
    long_description = fh.read()

requirements = ["coloredlogs", "netaddr", "nmap", "tenable_io"]
test_requirements = ["pytest", "pytest-watch", "pytest-cov", "flake8"]
setup_requirements = ["pytest-runner", "setuptools>=40.5.0"]

extras = {"test": test_requirements}

setup(
    name="vautomator",
    version="0.0.1",
    author="Mozilla Infosec",
    author_email="infosec@mozilla.com",
    description="VAutomator.",
    long_description=long_description,
    url="https://github.com/mozilla/vautomator",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Operating System :: OS Independent",
    ],
    install_requires=requirements,
    license="Mozilla Public License 2.0",
    setup_requires=setup_requirements,
    tests_require=test_requirements,
    extras_require=extras,
    test_suite="tests",
    zip_safe=True,
)
