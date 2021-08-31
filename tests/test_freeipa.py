#python
'''
Testing of the freeipa submodule
'''

import unittest

import ldap3_directories.freeipa


class TestDummy(unittest.TestCase):
	'''
	Dummy test, for syntax checking
	'''

	def test_module(self):
		'''
		Dummy test for the freeipa submodule (syntax check)
		'''

		self.assertIs(None, None)

