#python
'''
Testing of the main module
'''

import unittest

import ldap3_directories


class TestDummy(unittest.TestCase):
	'''
	Dummy test, for syntax checking
	'''

	def test_module(self):
		'''
		Dummy test for the module (syntax check)
		'''

		self.assertIs(None, None)

