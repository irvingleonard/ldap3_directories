#! python
'''FreeIPA directory
This module simplifies the use of the FreeIPA diretory service.

ToDo:
- Everything
'''

import getpass
import logging
import pathlib
import urllib.parse

import ldap3
import simplifiedapp

try:
	import ldap3_
except ImportError:
	import ldap3_directories.ldap3_ as ldap3_

LOGGER = logging.getLogger(__name__)


class IPAEtc:
	'''Internal IPA configuration
	LDAP branch holding the IPA configuration
		
	ToDo:
	- Documentation
	'''
	
	_entry_types = {
		'ipaConfig'	: 'cn=ipaConfig',
	}

	def __init__(self, connection, dry_run = False):
		
		self._connection = connection
		self._dry_run = dry_run
		
	def __getattr__(self, name):
		'''Lazy instantiation
		Some computation that is left pending until is needed.
		
		ToDo: Documentation
		'''
		
		if name in self._entry_types.keys():
			value = self._connection.get_entry_by_dn(self._entry_types[name], 'cn=etc', is_relative = True)
		elif name == 'user_definition':
			value = ldap3.ObjectDef(list(self.ipaConfig.ipaUserObjectClasses), self._connection)
		elif name == 'group_definition':
			value = ldap3.ObjectDef(list(self.ipaConfig.ipaGroupObjectClasses), self._connection)
		else:
			raise AttributeError(name)
		self.__setattr__(name, value)
		return value


class IPAUser(ldap3_.RWEntryWrapper):
	'''User wrapper
	An EntryWrapper that wraps the original user entry to add some functionality
		
	ToDo:
	- Documentation
	'''
	
	def change_password(self, new_password, old_password = ''):
		'''Change user password
		Old password empty should work with new accounts
		
		ToDo:
		- Documentation
		'''
		
		LOGGER.debug("Changing password for %s", self.entry_dn)
		return self.entry_cursor.connection.extend.standard.modify_password(self.entry_dn, old_password, new_password)


class IPAUsers(ldap3_.EntriesCollection):
	'''Collection of users
	Users in FreeIPA live in a single level. They're mapped into this collection.
		
	ToDo:
	- Documentation
	'''

	def __init__(self, directory, dry_run = False):
		'''Magic initialization method
		
		ToDo: Documentation
		'''

		super().__init__(connection = directory._connection, parent_dn = 'cn=users,cn=accounts', identity_attribute = 'uid', entry_customizer = IPAUser, object_definition = directory.etc.user_definition, dry_run = dry_run)
		self._directory = directory
	
	def _get_next_uid_number(self):
		'''Get a free UID number
		Find the next usable UID number. It will find the lowest free number that is higher than the lowest existing uidNumber. This can break in all kinds of way, mostly in heavy write parallel scenarios; use carefully.
		
		ToDo:
		- Documentation
		'''
		
		self._connection.search(search_base = self._connection.build_dn(self._collection_dn, is_relative = True), search_filter = '(objectclass=posixaccount)', attributes = 'uidNumber')
		uidNumbers = [entry['attributes']['uidNumber'] for entry in self._connection.response]
		uidNumbers.sort()
		
		possibleUID = uidNumbers[0]
		for uidN in uidNumbers:
			if uidN != possibleUID:
				break
			possibleUID += 1
		return possibleUID
	
	def add(self, uid, givenName, sn, **attributes):
		'''Create a new user
		Create a user based on the information provided; try to guess some information too.
		
		ToDo:
		- Documentation
		'''
		
		LOGGER.debug('Creating user with: %s', {'uid' : uid, 'givenName' : givenName, 'sn' : sn} | attributes)
		
		if len(uid):
			attributes['uid'] = uid
		else:
			raise ValueError("UID can't be empty")

		if len(givenName):
			attributes['givenName'] = givenName
		else:
			raise ValueError("First name can't be empty")

		if len(sn):
			attributes['sn'] = sn
		else:
			raise ValueError("Last name can't be empty")
		
		if 'cn' not in attributes:
			attributes['cn'] = ' '.join((givenName, sn))
		
		if 'displayName' not in attributes:
			attributes['displayName'] = attributes['cn']
		
		if 'initials' not in attributes:
			attributes['initials'] = str(attributes['givenName'])[0] + str(attributes['sn'])[0]
		
		if 'gecos' not in attributes:
			attributes['gecos'] = attributes['cn']
		
		if 'uidNumber' not in attributes:
			attributes['uidNumber'] = self._get_next_uid_number()
		
		if 'gidNumber' not in attributes:
			attributes['gidNumber'] = attributes['uidNumber']
		
#        if 'krbcanonicalname' not in attributes:
#             attributes['krbcanonicalname'] = '{}@{}'.format(uid, base_domain.upper())
			
		# if 'krbPrincipalName' not in attributes:
		# 	attributes['krbPrincipalName'] = '{}@{}'.format(uid, base_domain.upper())
		
		if 'loginShell' not in attributes:
			attributes['loginShell'] = str(self._directory.etc.ipaConfig.ipaDefaultLoginShell)
		
		if 'homeDirectory' not in attributes:
			attributes['homeDirectory'] = str(pathlib.Path(str(self._directory.etc.ipaConfig.ipaHomesRootDir)) / uid)
			
		if 'mail' not in attributes:
			attributes['mail'] = '{}@{}'.format(uid, self._directory.etc.ipaConfig.ipaDefaultEmailDomain)
		
		LOGGER.warning('Creating user: %s', attributes)

		return super().add(**attributes)


class IPAGroups(ldap3_.EntriesCollection):
	'''Collection of groups
	Groups in FreeIPA live in a single level. They're mapped into this collection.
		
	ToDo:
	- Documentation
	'''

	def __init__(self, directory, dry_run = False):
		'''Magic initialization method
		
		ToDo: Documentation
		'''

		super().__init__(connection = directory._connection, parent_dn = 'cn=groups,cn=accounts', object_definition = directory.etc.group_definition, dry_run = dry_run)
		self._directory = directory


class IPADirectory:
	'''Directory level
	This class models the FreeIPA directory as a whole.
		
	ToDo:
	- Documentation
	'''
	
	_LDAP_CONNECTION_PARAMS = {
#       'auto_bind'			: ldap3.AUTO_BIND_TLS_BEFORE_BIND,
		'auto_bind'			: True,
#       'authentication'	: ldap3.SIMPLE,
		'lazy'				: True,
		'raise_exceptions'	: True,
	}

	def __init__(self, servers, base_dn, username = None, password = None, dry_run = False):
		'''Instance initialization
		The LDAP connection is established
		
		ToDo:
		- Implement logout (and call it on __del__)
		'''
		
		if (username is None) or not len(username):
			username = input('Username: ')
			password = getpass.getpass('Password: ')
		
		if password is None:
			raise RuntimeError("Kerberos' keytab authentication is not implemented yet.")
		
		else:	
			cluster = ldap3.ServerPool([ldap3.Server(server, use_ssl = True) for server in (servers.split(' ') if isinstance(servers, str) else servers)], ldap3.FIRST, active = 1, exhaust = True)
			self._connection = ldap3_.Connection(server = cluster, base_dn = base_dn, user = 'uid={},cn=users,cn=accounts,{}'.format(username, base_dn), password = password, **self._LDAP_CONNECTION_PARAMS)
		
		self._dry_run = dry_run
	
	def __getattr__(self, name):
		'''Lazy initialization of collections
		Collections get initialized only when needed
		
		ToDo:
		- Documentation
		'''
		
		if name == 'etc':
			value = IPAEtc(connection = self._connection, dry_run = self._dry_run)
		elif name == 'users':
			value = IPAUsers(directory = self, dry_run = self._dry_run)
		elif name == 'groups':
			value = IPAGroups(directory = self, dry_run = self._dry_run)
		else:
			raise AttributeError(name)
		setattr(self, name, value)
		return value


if __name__ == '__main__':
	simplifiedapp.main()