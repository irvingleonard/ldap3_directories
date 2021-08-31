#python
'''
Testing of ldap3 enhancements in ldap3_directories
'''

import unittest

import ldap3

import ldap3_directories.ldap3_


def populate_dit(connection):
	connection.strategy.add_entry('cn=admin,dc=example,dc=com', {'userPassword': 'a password?', 'objectClass' : ['top', 'posixAccount'], 'revision': 0})
	connection.strategy.add_entry('ou=people,dc=example,dc=com', {'objectClass' : ['top'], 'revision': 0})
	connection.strategy.add_entry('uid=alice,ou=people,dc=example,dc=com', {'objectClass' : ['top'], 'revision': 0})
	connection.strategy.add_entry('uid=bob,ou=people,dc=example,dc=com', {'objectClass' : ['top'], 'revision': 0})
	return connection


class TestConnection(unittest.TestCase):
	'''
	Tests for the Connection class
	'''
	
	def setUp(self):
		self.connection = ldap3_directories.ldap3_.Connection(ldap3.Server('mock_server'), user='cn=admin,dc=example,dc=com', password='a password?', base_dn = 'dc=example,dc=com', client_strategy = ldap3.MOCK_SYNC)
		self.connection = populate_dit(self.connection)
		self.connection.bind()
		self.maxDiff = None


	def test_get_entry_by_dn_missing(self):
		'''
		Test error: get_entry_by_dn on missing entry
		'''

		self.assertRaises(RuntimeError, self.connection.get_entry_by_dn, 'uid=john', 'ou=people', is_relative = True)

	def test_build_dn_w_str(self):
		'''
		Test build_dn with a string
		'''

		self.assertEqual(self.connection.build_dn('ou=groups,dc=example,dc=com'), 'ou=groups,dc=example,dc=com')

	def test_build_dn_w_params(self):
		'''
		Test build_dn with positional parameters
		'''

		self.assertEqual(self.connection.build_dn('ou=groups', 'dc=example', 'dc=com'), 'ou=groups,dc=example,dc=com')

	def test_build_dn_w_params_relative(self):
		'''
		Test build_dn with positional parameters and relative flag
		'''

		self.assertEqual(self.connection.build_dn('uid=alice', 'ou=people', is_relative = True), 'uid=alice,ou=people,dc=example,dc=com')

	def test_get_entry_by_dn(self):
		'''
		Test get_entry_by_dn with existing entry
		'''

		self.assertIsInstance(self.connection.get_entry_by_dn('uid=alice', 'ou=people', is_relative = True), ldap3.Entry)


class TestConnectionExceptions(unittest.TestCase):
	'''
	Tests for the Connection class raising exceptions
	'''
	
	def setUp(self):
		self.connection = ldap3_directories.ldap3_.Connection(ldap3.Server('mock_server'), user='cn=admin,dc=example,dc=com', password='a password?', base_dn = 'dc=example,dc=com', raise_exceptions = True, client_strategy = ldap3.MOCK_SYNC)
		self.connection = populate_dit(self.connection)
		self.connection.bind()
		self.maxDiff = None

	def test_get_entry_by_dn_missing(self):
		'''
		Test error: get_entry_by_dn on missing entry
		'''

		self.assertRaises(ValueError, self.connection.get_entry_by_dn, 'uid=john', 'ou=people', is_relative = True)

class TestConnectionLegacy(unittest.TestCase):
	'''
	Tests for the Connection class raising exceptions
	'''
	
	def setUp(self):
		self.connection = ldap3_directories.ldap3_.Connection(ldap3.Server('mock_server'), user='cn=admin,dc=example,dc=com', password='a password?', client_strategy = ldap3.MOCK_SYNC)
		self.connection = populate_dit(self.connection)
		self.connection.bind()
		self.maxDiff = None

	def test_connection_legacy(self):
		'''
		Test connection without the base_dn parameter
		'''

		with self.assertLogs(ldap3_directories.ldap3_.LOGGER, level='DEBUG') as cm:
			ldap3_directories.ldap3_.Connection(ldap3.Server('mock_server'), user='cn=admin,dc=example,dc=com', password='a password?', client_strategy = ldap3.MOCK_SYNC)
			self.assertEqual(cm.output, ['DEBUG:ldap3_directories.ldap3_:Connection created without a base_dn'])

	def test_build_dn_w_params_relative(self):
		'''
		Test error: build_dn relative on legacy connection
		'''

		self.assertRaises(RuntimeError, self.connection.build_dn, 'uid=alice', 'ou=people', is_relative = True)

	def test_get_entry_by_dn(self):
		'''
		Test error: get_entry_by_dn relative on legacy connection
		'''

		self.assertRaises(RuntimeError, self.connection.get_entry_by_dn, 'uid=alice', 'ou=people', is_relative = True)