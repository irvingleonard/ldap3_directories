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

import dns.resolver
import ldap3
import ldap3.core.exceptions
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
		'Realm_Domains'	: 'cn=Realm Domains,cn=ipa',
		'ipaConfig'		: 'cn=ipaConfig',
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
	
	def __bool__(self):
		'''Check lock status
		Work the nsAccountLock operational attribute to find out the lock status: True = enabled; False = disabled
		
		ToDo:
		- Documentation
		'''

		if hasattr(self, 'nsAccountLock') and self.nsAccountLock.value == 'True':
			return False
		else:
			return True

	def connect_to_directory(self, password):

		LOGGER.debug('Connecting to the directory as user %s', self.uid)
		try:
			connection = ldap3_.Connection(self.entry_cursor.connection.server_pool, base_dn = self.entry_cursor.connection.base_dn, user = self.entry_dn, password = password, auto_bind = True, lazy = False, raise_exceptions = True)
		except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
			raise ValueError("The password provided didn't work")
		else:
			LOGGER.debug('Succesfully connected to the directory as %s', self.uid)
			return connection

	def change_password(self, new_password, old_password = ''):
		'''Change user password
		Old password empty should work with new accounts
		
		ToDo:
		- Documentation
		'''
		
		if len(old_password):
			LOGGER.debug("Changing password for user %s", self.uid)
			try:
				user_connection = self.connect_to_directory(old_password)
			except ValueError:
				raise ValueError("The current password doesn't match")
			else:
				return user_connection.extend.standard.modify_password(self.entry_dn, old_password, new_password)
		else:
			LOGGER.debug("Resetting password for user %s", self.uid)
			return self.entry_cursor.connection.extend.standard.modify_password(self.entry_dn, '', new_password)

	def user_status(self, enable = None):
		'''User enable/disable
		Enables or disables the user. With the enable flag=None (default) will return current status; enable=True will enable, enable=False will disable.
		
		ToDo:
		- Documentation
		'''

		if enable is None:
			return bool(self)
		elif enable:
			if self:
				LOGGER.warning('User %s is already enabled', self.uid)
				return True
			else:
				LOGGER.debug('Enabling user %s', self.uid)
				return self.entry_cursor.connection.modify(self.entry_dn, {'nsAccountLock' : (ldap3.MODIFY_REPLACE, [False])})
		else:
			if self:
				LOGGER.debug('Disabling user %s', self.uid)
				return not self.entry_cursor.connection.modify(self.entry_dn, {'nsAccountLock' : (ldap3.MODIFY_REPLACE, [True])})
			else:
				LOGGER.warning('User %s is already disabled', self.uid)
				return False


class IPAUsers(ldap3_.EntriesCollection):
	'''Collection of users
	Users in FreeIPA live in a single level. They're mapped into this collection.
		
	ToDo:
	- Documentation
	'''

	_entry_attributes = ('*', '+')

	def __init__(self, directory, dry_run = False):
		'''Magic initialization method
		
		ToDo: Documentation
		'''

		super().__init__(connection = directory._connection, collection_rdn = 'cn=users,cn=accounts', identity_attribute = 'uid', entry_customizer = IPAUser, object_definition = directory.etc.user_definition, dry_run = dry_run)
		self._directory = directory

	def _get_next_uid_number(self):
		'''Get a free UID number
		Find the next usable UID number. It will find the lowest free number that is higher than the lowest existing uidNumber. This can break in all kinds of way, mostly in heavy write parallel scenarios; use carefully.
		
		ToDo:
		- Documentation
		'''
		
		self._connection.search(search_base = self._connection.build_dn(self._collection_rdn, is_relative = True), search_filter = '(objectclass=posixaccount)', attributes = 'uidNumber')
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
		
		LOGGER.debug('Creating user with: %s, %s', {'uid' : uid, 'givenName' : givenName, 'sn' : sn}, attributes)
		
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
		
		if 'krbCanonicalName' not in attributes:
			attributes['krbCanonicalName'] = '{}@{}'.format(uid, self._directory.etc.Realm_Domains.associatedDomain.value.upper())
			
		if 'krbPrincipalName' not in attributes:
			attributes['krbPrincipalName'] = attributes['krbCanonicalName']
		
		if 'loginShell' not in attributes:
			attributes['loginShell'] = str(self._directory.etc.ipaConfig.ipaDefaultLoginShell)
		
		if 'homeDirectory' not in attributes:
			attributes['homeDirectory'] = str(pathlib.Path(str(self._directory.etc.ipaConfig.ipaHomesRootDir)) / uid)
			
		if 'mail' not in attributes:
			attributes['mail'] = '{}@{}'.format(uid, self._directory.etc.ipaConfig.ipaDefaultEmailDomain)

		collection_dn = self._connection.build_dn(self._collection_rdn, is_relative = True)
		if ('manager' in attributes) and (attributes['manager'].find(collection_dn) < 0):
			attributes['manager'] = self[attributes['manager']].entry_dn
		
		LOGGER.info('Creating user: %s', attributes)
		new_user = super().add(**attributes)
		
		LOGGER.debug('Adding new user to default group: %s', self._directory.groups.primary_default)
		self._directory.groups.primary_default += new_user
		
		return new_user


class IPAGroup(ldap3_.RWEntryWrapper):
	'''Group wrapper
	An EntryWrapper that wraps the original group entry to add some functionality
		
	ToDo:
	- Documentation
	'''
	
	def __iadd__(self, other):
		'''Add member to group
		The only requirement is that the "other" should have an entry_dn attribute that can actually become a member of the group.
		'''
		
		if self.entry_is_writable:
			if other.entry_dn in self.member:
				LOGGER.info('Group %s already has a member %s', self.cn, other.entry_dn)
			else:
				LOGGER.debug('Group %s is getting a new member %s', self.cn, other.entry_dn)
				self.member.add(other.entry_dn)
				self.entry_commit_changes()
		else:
			raise RuntimeError('Entry seems to be read-only')

	def __isub__(self, other):
		'''Remove member to group
		The only requirement is that the "other" should have an entry_dn attribute which is already a member of the group.
		'''

		if self.entry_is_writable:
			if other.entry_dn in self.member:
				LOGGER.debug('Group %s is losing a member %s', self.cn, other.entry_dn)
				self.member.delete(other.entry_dn)
				self.entry_commit_changes()
			else:
				LOGGER.info("Group %s doesn't has a member %s", self.cn, other.entry_dn)
		else:
			raise RuntimeError('Entry seems to be read-only')


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

		super().__init__(connection = directory._connection, collection_rdn = 'cn=groups,cn=accounts', entry_customizer = IPAGroup, object_definition = directory.etc.group_definition, dry_run = dry_run)
		self._directory = directory
	
	def __getattr__(self, name):
		'''Lazy instantiation
		Some computation that is left pending until is needed.
		
		ToDo: Documentation
		'''
		
		if name == 'primary_default':
			value = self[str(self._directory.etc.ipaConfig.ipaDefaultPrimaryGroup)]
		else:
			raise AttributeError(name)
		self.__setattr__(name, value)
		return value
	
	def add(self, name, **attributes):

		if len(name):
			attributes['cn'] = name
		else:
			raise ValueError("Name can't be empty")

		return super().add(**attributes)


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

	def __init__(self, domain_name, username = None, password = None, dry_run = False):
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
		
		srv_records = {}
		for srv_record in dns.resolver.resolve('_ldap._tcp.{}'.format(domain_name), 'SRV'):
			if srv_record.weight not in srv_records:
				srv_records[srv_record.weight] = []
			srv_records[srv_record.weight].append(srv_record)
		weights = list(srv_records)
		weights.sort()		
		
		servers = []
		for weight in weights:
			servers += [str(srv_record.target) for srv_record in srv_records[weight]]
		cluster = ldap3.ServerPool([ldap3.Server(server, use_ssl = True) for server in servers], ldap3.FIRST, active = 1, exhaust = True)
		
		base_dn = self.domain_to_dn(domain_name)
		
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
	
	@staticmethod
	def domain_to_dn(domain):
		
		dn = domain.split('.')
		dn = ['dc={}'.format(part) for part in dn]
		return ','.join(dn)
		

if __name__ == '__main__':
	simplifiedapp.main()
