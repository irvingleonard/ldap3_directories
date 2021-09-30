#python
'''
Testing of ldap3 enhancements in ldap3_directories
'''

import unittest

import ldap3

import ldap3_directories.ldap3_

class TestQueryJoin(unittest.TestCase):
	'''
	Tests for the QueryJoin class
	'''
	
	def setUp(self):
		self.test_object = ldap3_directories.ldap3_.QueryJoin
		self.maxDiff = None

	def test_empty_join(self):
		'''
		Test query join with empty join
		'''

		self.assertEqual(str(self.test_object('&')), '')

	def test_single_element(self):
		'''
		Test query join with a single element
		'''

		self.assertEqual(str(self.test_object('&', '(givenName=John)')), '(givenName=John)')

	def test_two_elements(self):
		'''
		Test query join with a two elements
		'''

		self.assertEqual(str(self.test_object('&', '(givenName=John)', '(objectClass=*)')), '(&(givenName=John)(objectClass=*))')

	def test_multiple_elements(self):
		'''
		Test query join with a two elements
		'''

		self.assertEqual(str(self.test_object('|', '(givenName=John)', '(objectClass=*)', '(targetAttribute>=10)', '(cn=*John*Doe*)', '(givenName~=John)')), '(|(givenName=John)(objectClass=*)(targetAttribute>=10)(cn=*John*Doe*)(givenName~=John))')

	def test_negation(self):
		'''
		Test query join negation
		'''

		self.assertEqual(-self.test_object('|', '(givenName=John)', '(objectClass=*)', '(targetAttribute>=10)', '(cn=*John*Doe*)', '(givenName~=John)'), '(!(|(givenName=John)(objectClass=*)(targetAttribute>=10)(cn=*John*Doe*)(givenName~=John)))')


class TestQueryAssertion(unittest.TestCase):
	'''
	Tests for the QueryAssertion class
	'''
	
	def setUp(self):
		self.test_object = ldap3_directories.ldap3_.QueryAssertion
		self.maxDiff = None

	def test_implicit_equality(self):
		'''
		Test query assertion with implicit equality
		'''

		self.assertEqual(self.test_object('givenName', 'John'), '(givenName=John)')

	def test_explicit_equality(self):
		'''
		Test query assertion with explicit equality
		'''

		self.assertEqual(self.test_object('givenName', 'John', '='), '(givenName=John)')

	def test_presence(self):
		'''
		Test query assertion for presence
		'''

		self.assertEqual(self.test_object('objectClass', '*'), '(objectClass=*)')

	def test_greater_or_equal(self):
		'''
		Test query assertion with greater or equal
		'''

		self.assertEqual(self.test_object('targetAttribute', 10, '>='), '(targetAttribute>=10)')

	def test_less_or_equal(self):
		'''
		Test query assertion with less or equal
		'''

		self.assertEqual(self.test_object('targetAttribute', 10, '<='), '(targetAttribute<=10)')

	def test_substring(self):
		'''
		Test query assertion with substring
		'''

		self.assertEqual(self.test_object('cn', '*John*Doe*'), '(cn=*John*Doe*)')

	def test_approximate_match(self):
		'''
		Test query assertion with approximate match
		'''

		self.assertEqual(self.test_object('givenName', 'John', '~='), '(givenName~=John)')

	def test_negation(self):
		'''
		Test query assertion negated
		'''

		self.assertEqual(-self.test_object('givenName', 'John'), '(!(givenName=John))')
