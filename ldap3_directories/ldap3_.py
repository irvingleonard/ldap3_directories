#! python
'''LDAP3 enhancements
Some enhancements to existing ldap3 module classes and other new classes.

ToDo:
- Everything
'''

import functools
import logging
import operator

import ldap3
import ldap3.core.exceptions

LOGGER = logging.getLogger(__name__)


class QueryJoin(list):
	'''Modeling an LDAP filter join
	It joins LDAP assertions or other joins: (<operation>(part)(part)...)
	'''

	def __init__(self, operation, *parts):
		'''Initialization magic
		It's a simple list, plus the operation information, which is saved on an attribute
		'''
		
		super().__init__()
		self.ldap_operation = operation
		self.extend(parts)

	def __repr__(self):
		'''Repr magic
		Ready to be eval'd
		'''

		return '{class_}({params})'.format(class_ = self.__class__.__name__, params = ', '.join([repr(param) for param in [self.ldap_operation] + self]))

	def __str__(self):
		'''Str magic
		The actual result, the computation of the filter.
		'''

		if len(self) == 0:
			return ''
		elif len(self) == 1:
			return str(self[0])
		else:
			return '({}{})'.format(self.ldap_operation, ''.join([str(item) for item in self]))

	def __neg__(self):
		'''Magic method for unary minus
		It negates the current assertion.
		'''

		if len(self):
			return '(!{})'.format(self)
		else:
			return ''


class QueryAssertion(str):
	'''Modeling an LDAP assertion
	This is a simple model for an LDAP assertion: (attribute<operation>value).

	Ex:
	(cn=example_entry)
	(objectClass=*)
	'''

	def __new__(cls, attribute, value, comparison = '='):
		'''Magic method to create instance
		It creates the underlying string instance based on the values provided.
		'''
		
		return super().__new__(cls, '({}{}{})'.format(attribute, comparison, value))

	def __neg__(self):
		'''Magic method for unary minus
		It negates the current assertion.
		'''

		return '(!{})'.format(self)


class Connection(ldap3.Connection):
	
	def __init__(self, *args, base_dn = None, **kwargs):
		'''Magic initialization method
		
		Add the base_dn to the object, used by other code down the line.
		'''
		
		super().__init__(*args, **kwargs)
		if base_dn is None:
			LOGGER.debug('Connection created without a base_dn')
		self.base_dn = base_dn

	def build_dn(self, *components, is_relative = False):
		'''Build a DN based on components
		Several "parts" can be provided and they will be joined together; the is_relative flag would add the connection's base DN to the mix.
		
		ToDo:
		- Documentation
		'''

		if is_relative and (self.base_dn is None):
			raise RuntimeError('Relative DNs are not supported on this connection (base_dn is missing)')

		return ','.join(components + ((self.base_dn,) if is_relative else ()))

	def get_entry_by_dn(self, *dn, is_relative = False, attributes = '*'):
		'''Get entry by DN
		Retrieve a single entry described by the provided DN. The underlying function is ldap3's search.
		
		ToDo:
		- Documentation
		'''

		dn = self.build_dn(*dn, is_relative = is_relative)
		try:
			result_bool = self.search(search_base = dn, search_filter = '(objectClass=*)', search_scope = ldap3.BASE, attributes = attributes)
		except ldap3.core.exceptions.LDAPNoSuchObjectResult:
			raise ValueError('No entry found for dn: {}'.format(dn))
		else:
			if not result_bool:
				raise RuntimeError('Search failed for {}'.format(dn))
			if len(self.response) > 1:
				raise AttributeError('The dn "{}" yield too many ({}) results'.format(dn, len(self.entries)))
			elif not len(self.response):
				raise ValueError('No entry found for dn: {}'.format(dn))
			return self.entries[0]


class EntriesCollection(dict):
	'''Entry collection from server schema
	Access a collection of entries using the identifying attribute as key of the dict.
	
	ToDo:
	- Documentation
	'''
	
	_entry_attributes = ldap3.ALL_ATTRIBUTES

	def __init__(self, connection, collection_rdn, identity_attribute = 'cn', entry_customizer = None, object_definition = None, dry_run = False):
		'''Magic initialization method
		
		ToDo: Documentation
		'''
	
		super().__init__()
		self._connection = connection
		self._identity_attribute = identity_attribute
		self._collection_rdn = collection_rdn
		self._entry_customizer = entry_customizer
		self._object_definition = object_definition
		self._dry_run = dry_run

	def __delitem__(self, name):
		'''Delete an existing entry
		Leverages the the entry.delete_entry method to actually delete entries in the collection.
		
		ToDo:
		- Documentation
		'''

		try:
			existing_entry = self[name]
		except KeyError:
			raise KeyError("Can't delete entry {}; it doesn't exist".format(name))
		
		if not self._connection.delete(existing_entry.entry_dn):
			raise RuntimeError('Deletion of entry {} failed'.name)

		return super().__delitem__(name)

	def __missing__(self, name):
		'''Lazy retrieval of entries
		The LDAP traffic will happen only when an entry is needed.
		
		ToDo: Documentation
		'''
		
		dn = self._build_dn(name)
		try:
			entry = self._connection.get_entry_by_dn(dn, attributes = self._entry_attributes)
		except ValueError:
			raise KeyError("Couldn't find entry {}".format(name))
		# LOGGER.debug('Got entry for %s: %s', dn, entry)
		
		if self._entry_customizer is not None:
			entry = self._entry_customizer(entry = entry, dry_run = self._dry_run)

		self.__setitem__(name, entry)
		return entry
	
	def _build_dn(self, name):
		'''Build the DN for a member
		Uses the underlying connection.build_dn method and the collection description to build a DN. Returns the absolute DN of such member.
		
		ToDo:
		- Documentation
		'''

		return self._connection.build_dn('{}={}'.format(self._identity_attribute, name), self._collection_rdn, is_relative = True)

	def add(self, **attributes):
		'''Create a new entry
		Create an entry in this collection based on the information provided.
		
		ToDo:
		- Documentation
		'''
		
		if self._object_definition is None:
			raise RuntimeError('No object_definition provided. Entry creation is not possible.')

		if self._identity_attribute not in attributes:
			raise ValueError('Identity attribute "{}" was not provided'.format(self._identity_attribute))

		dn = self._build_dn(attributes[self._identity_attribute])
		LOGGER.debug('Creating entry %s with: %s', dn, attributes)
		
		if self._connection.add(dn, self._object_definition._object_class, attributes):
			return self[attributes[self._identity_attribute]]
		else:
			raise RuntimeError('User creation failed: {}'.format(attributes))

	def advanced_search(self, *args, entry_attributes = None, **kwargs):
		'''Classic advanced search
		Equality search filter created with a combination of AND and OR operations.
		
		The algorithm works as follows:
		- The keyword parameters are expected to be ldap_attr=values
		- The keyword parameters will be converted to LDAP assertions
		- Multiple values for a single attributed will be ORed together
		- Positional parameters should be valid filters (assertions, or assertion joins)
		- All the assertions, "assertions OR joins", and positional parameters will be ANDed together
		
		ToDo: Documentation
		'''
		
		LOGGER.debug('Performing an advanced search with: %s | %s', args, kwargs)
		query = QueryJoin('&', *args)
		for attr_name, attr_values in kwargs.items():
			if len(attr_values):
				if isinstance(attr_values, str):
					query.append(QueryAssertion(attr_name, attr_values))
				else:
					query.append(QueryJoin('|', *[QueryAssertion(attr_name, value) for value in attr_values]))
			else:
				raise NotImplementedError('Search for absent attribute')
		
		if entry_attributes is None:
			entry_attributes = (self._identity_attribute,)
		else:
			if isinstance(entry_attributes, str):
				entry_attributes = (entry_attributes,)
			entry_attributes = (self._identity_attribute,) + tuple(entry_attributes)

		LOGGER.debug('Querying LDAP server with: %s', query)
		self._connection.search(search_base = self._connection.build_dn(self._collection_rdn, is_relative = True), search_filter = str(query), attributes = entry_attributes)
		LOGGER.debug('Got %d hits for the query', len(self._connection.response))

		if len(entry_attributes) == 1:
			result = [entry['attributes'][self._identity_attribute][0] if isinstance(entry['attributes'][self._identity_attribute], list) else entry['attributes'][self._identity_attribute] for entry in self._connection.response]
			return {identity_value : self[identity_value] for identity_value in result}
		else:
			result = {}
			for entry in self._connection.response:
				id_attr = entry['attributes'][self._identity_attribute][0] if isinstance(entry['attributes'][self._identity_attribute], list) else entry['attributes'][self._identity_attribute]
				result[id_attr] = {attr_name : entry['attributes'][attr_name] for attr_name in entry_attributes}
			return result


	def update(self, other, lazy = True):
		'''Merge mapping into the collection
		Update existing entries with info from "other" which is expected to be a mapping in the form id_attr->{attribute->values}
		
		ToDo: Documentation
		'''
		
		result = {}
		for entry_id, entry_attr in other.items():
			
			try:
				entry = self[entry_id]
			except Exception:
				try:
					self.create(**entry_attr)
				except Exception:
					LOGGER.exception('Creation of entry "{}" failed.'.format(entry_id))
				continue
			
			LOGGER.debug('Updating entry %s: %s', self._identity_attribute, entry_id)
			for attr_key, attr_value in entry_attr.items():
				setattr(entry, attr_key, attr_value)
			
			changes = entry.report_changes()
			if len(changes):
				result[entry_id] = changes
				if lazy:
					LOGGER.debug('Postponing the update of entry %s: %s', self._identity_attribute, entry_id)
				else:
					LOGGER.info('Pushing entry update %s: %s', self._identity_attribute, entry_id)
					if self._dry_run:
						LOGGER.info("Skipping actual changes push since it's a dry run")
					else:
						try:
							entry.entry_commit_changes()
						except Exception:
							LOGGER.exception('Update of entry "{}" failed.'.format(entry_id))
				
		return result


class RWEntryWrapper:
	'''ORM Entry RW capable
	This class hides away some of the processes required to use the underlying ORM. You can use read-only entries or write-only entries. With this you get a read&write entries.
	
	- Read/write distinctions are gone. Just write to it and that's it.
	- Writing the same values into attributes will be ignored. The list of changes will contain actual changes opposed to "operations requested"
	- Deleting an attribute does that: it deletes the attribute 'del entry.attr'
	- By asking for the entry_is_writable it's assumed that a method will try to change something, which means that the read-only -> read&write conversion will be performed
		
	ToDo: Documentation
	'''
	
	_local_attributes = (
		'_dry_run',
		'_entry',
		'_local_attributes',
		'_original_entry',
		'entry_is_writable',
	)

	def __init__(self, entry, dry_run = False):
		'''Magic initialization method
		
		ToDo: Documentation
		'''
		
		LOGGER.debug('Wrapping entry: %s', entry.entry_dn)
		self._entry = entry
		self._dry_run = dry_run
	
	def __del__(self):
		'''Lazy update
		Pending changes get pushed on termination
		
		ToDo: Documentation
		'''
		
		if  self.entry_is_writable and len(self._changes):
			if self._dry_run:
				LOGGER.info("Not pushing changes for entry %s since it's a dry run", self.entry_dn)
			else:
				LOGGER.debug('Pushing updates for entry %s: %s', self.entry_dn, self._changes)
				self.entry_commit_changes()
		else:
			LOGGER.debug('No changes for entry %s', self.entry_dn)
	
	def __dir__(self):
		'''Magic dir method
		Merge the wrapper and inner entry dirs
		
		ToDo: Documentation
		'''

		values = dir(self._entry)
		values += [value for value in super().__dir__() if value not in values]
		values.sort()
		return values

	def __getattr__(self, name):
		'''Expose inner entry attributes
		If the wrapper doesn't have such attribute it must be part of the inner entry.
		'''
		
		if name == 'entry_is_writable':
			# Switch to a writable entry
			# The underlying ORM (ldap3) uses read-only Entry objects that need to be converted to a writable version. This method does that, it also saves the original read-only entry in self._original_entry
			if self.entry_status.lower() in ('read',):
				w_entry = self.entry_writable()
				self._original_entry = self._entry
				self._entry = w_entry
				setattr(self, 'entry_is_writable', True)
				return True
			elif self.entry_status.lower() in ('writable',):
				setattr(self, 'entry_is_writable', True)
				return True
			else:
				raise RuntimeError('Unhandled entry state: {}'.format(self.entry_status))
		else:
			return getattr(self._entry, name)
	
	def __setattr__(self, name, value):
		'''Attribute assignment separation
		Some attributes are part of the wrapper, most of them will be part of the inner entry. Plain overwrites (writing again the existing content) will be ignored in order to get a meaningful list of changes. Assigning 'None' will trigger a 'del name' instead.
		'''
		
		if name in self._local_attributes:
			return super().__setattr__(name, value)
		elif value is None:
			return delattr(self, name)
		elif self.entry_is_writable:
			attr = getattr(self._entry, name)
			if attr.value == value:
				LOGGER.debug('Skipping up-to-date attribute %s: %s', name, value)
				return
			else:
				LOGGER.debug('Updating attribute: %s = %s', name, value)
				return attr.set(value)
		else:
			raise RuntimeError('Entry is read-only, apparently')
	
	def __delattr__(self, name):
		'''Attribute deletion separation
		Some attributes are part of the wrapper, most of them will be part of the inner entry.
		'''
		
		if name in self._local_attributes:
			return super().__delattr__(name, value)
		elif not hasattr(self._entry, name):
			raise ValueError("Unable to delete non existing attribute {}".format(name))
		elif getattr(self._entry, name).value is None:
			LOGGER.debug('Skipping already removed attribute: %s', name)
		elif self.entry_is_writable:
			return getattr(self._entry, name).remove()
		else:
			raise RuntimeError('Entry is read-only, apparently')
			
	def __repr__(self):
		'''Expose inner entry repr
		Nothing better to do in the wrapper at this point.
		'''
		
		return self._entry.__repr__()
	
	def as_dict(self, skip_attrs = ()):
		'''Cast to dict
		Dicts are more useful for exporting and converting to other formats.
		'''
		
		result = {}
		for key, value in vars(self._entry).items():
			if (key not in skip_attrs) and (value is not None) and value and hasattr(value, 'definition') and hasattr(value.definition, 'single_value'):
				if value.definition.single_value:
					result[key] = value.value
				else:
					result[key] = value.values
		return result

	def report_changes(self, raw_changes = False):
		'''Report the pending changes
		Creates a dictionary with the changes in the form of: attribute->(original_value, new_value). If raw_changes is True it will return the content of _changes instead (the underlying dictionary of changes).
		'''
		
		if raw_changes:
			return self._changes
		
		changes = {}
		for key, operation in self._changes.items():
			old_value = getattr(self._original_entry, key).value if hasattr(self._original_entry, key) else None
			new_value = operation[0][1]
			changes[key] = (old_value, new_value[0] if len(new_value) else None)
		return changes
