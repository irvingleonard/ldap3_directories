# ldap3_directories

Includes some enhancements to the contents of the ldap3 module and adds some functionality to simplify the use of LDAP directories. Each submodule will target a specific directory.

## Enhancements

Some enhancements to the builtin [ldap3](https://pypi.org/project/ldap3/) features were required to accomodate some required functionalities.

### Connection

The [connection](https://ldap3.readthedocs.io/en/latest/connection.html) is used with a single base_dn (the base of the directory) that's why the attribute was added to the class. A couple of functionalities related to this idea are available now:
- `build_dn` will build a DN from an iterator and is also able to leverage the base_dn attribute to work with "relative" DNs
- `get_entry_by_dn` implements a heavely used functionality: it retrieves an entry identified by certain DN.

### EntriesCollection

This new class is intended to group similar entries on a dictionary, like all the users, all the groups, all the hosts, etc.

### RWEntryWrapper

This will wrap an [entry](https://ldap3.readthedocs.io/en/latest/abstraction.html#entry) and hide away the read vs write entries distinction. It also adds some extra functionality like reporting pending changes, entry deletion, entry export, etc.

## FreeIPA

This submodule is intended to work with the [FreeIPA](https://www.freeipa.org/page/Main_Page) directory. So far only the users and groups are supported. The kerberos authentication is not supported at this point. The servers are expected to be correctly configured, listening on 636 with SSL (it's currently hardcoded and not configurable).

### Examples

Instantiating an `IPADirectory`
```
import ldap3_directories.freeipa

servers = 'freeipa.example.com'	#servers could be a single server as a string
servers = 'freeipa0.example.com freeipa1.example.com'	#servers could be a space separated list as a string
servers = ('freeipa0.example.com', 'freeipa1.example.com')	#servers could be an iterator containing the servers as strings

base_dn = 'dc=mydir,dc=example,dc=com'	#base_dn will be the root of your directory

username = 'myuser.name'
password = 'my_very_secure_password'

freeipa = ldap3_directories.freeipa.IPADirectory(servers, base_dn, username, password)
```

Getting a user by it's UID
```
uid = 'some.user'
try:
	user_entry = freeipa.users[uid]
except KeyError:
	print("User {} wasn't found".format(uid))
else:
	print("User {}: {}".format(uid, user_entry))
```

Getting a group by it's name
```
group_name = 'ipausers'
try:
	group_entry = freeipa.groups[group_name]
except KeyError:
	print("Group {} wasn't found".format(group_name))
else:
	print("Group {}: {}".format(group_name, group_entry))
```

Add a new user to the directory
```
freeipa.users.add('new.user', 'New', 'User')
```

Delete an existing user from the directory
```
uid = 'new.user'
freeipa.users[uid].delete_entry()
```
