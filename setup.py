#!python
"""A setuptools based setup module.

ToDo:
- Everything
"""

import setuptools

import simplifiedapp

import ldap3_directories

setuptools.setup(
	url = 'https://github.com/irvingleonard/ldap3_directories',
	author = 'Irving Leonard',
	author_email = 'irvingleonard@gmail.com',
	license='BSD 2-Clause "Simplified" License',
	classifiers = [
		'Development Status :: 4 - Beta',
		'Intended Audience :: Developers',
		'License :: OSI Approved :: BSD License',
		'Natural Language :: English',
		'Operating System :: OS Independent',
		'Programming Language :: Python',
		'Programming Language :: Python :: 3',
		'Programming Language :: Python :: 3 :: Only',
		'Topic :: Software Development :: Libraries',
		'Topic :: Software Development :: Libraries :: Python Modules',
		'Topic :: System :: Systems Administration :: Authentication/Directory',
		'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
	],
	keywords = 'ldap ldap3 freeipa',
	python_requires = '>=3.7',
	install_requires=(
		'dnspython',
		'ldap3',
		'simplifiedapp',
	),
	packages = setuptools.find_packages(),
	
	**simplifiedapp.object_metadata(ldap3_directories)
)
