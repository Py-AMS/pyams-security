PyAMS passwords managers
========================

PyAMS provides several password managers, which can be used to encrypt users passwords.

    >>> import pprint

    >>> from pyramid.testing import tearDown, DummyRequest
    >>> from pyams_security.tests import setup_tests_registry, new_test_request
    >>> from pyramid.threadlocal import manager
    >>> config = setup_tests_registry()
    >>> config.registry.settings['zodbconn.uri'] = 'memory://'

    >>> from pyramid_zodbconn import includeme as include_zodbconn
    >>> include_zodbconn(config)
    >>> from cornice import includeme as include_cornice
    >>> include_cornice(config)
    >>> from pyams_utils import includeme as include_utils
    >>> include_utils(config)
    >>> from pyams_mail import includeme as include_mail
    >>> include_mail(config)
    >>> from pyams_site import includeme as include_site
    >>> include_site(config)
    >>> from pyams_catalog import includeme as include_catalog
    >>> include_catalog(config)
    >>> from pyams_file import includeme as include_file
    >>> include_file(config)
    >>> from pyams_security import includeme as include_security
    >>> include_security(config)


SSHA512 password manager
------------------------

The first manager is using SHA512 encrypted passwords:

    >>> from zope.interface.verify import verifyObject
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from pyams_security.password import SSHA512PasswordManager

    >>> manager = SSHA512PasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = "right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password, salt="")
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SSHA512}6rASd9HiiHImjuS6tI66vuAWLOWIIoy0J5EZkPEsN4MRmJwA5T+Ozfpo7SNYEwfodFsZ8sKdfzmVXzSkSVPgeg==

    >>> manager.match(encoded)
    True
    >>> manager.match(encoded.decode())
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + "wrong")
    False

    Our password manager generates the same value when seeded with the
    same salt, so we can be sure, our output is compatible with
    standard LDAP tools that also use SSHA:

    >>> from base64 import standard_b64decode
    >>> salt = standard_b64decode('ja/vZQ==')
    >>> password = 'secret'
    >>> encoded = manager.encodePassword(password, salt)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SSHA512}xW9ON4/woinDi8gLvxhpaKtPT3RSRoZh7S1Sm0LYM0ud1gDu2/dOICRCqUqAxhN/+hFWo6O/LOeHtEf6wDZ8ro2v72U=

    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + "wrong")
    False

    We can also pass a salt that is a text string:

    >>> salt = 'salt'
    >>> password = 'secret'
    >>> encoded = manager.encodePassword(password, salt)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SSHA512}E491yrR9AdCoE7rbOPYS3EZgSuZpVE65AD9xko08s6floNesY/Zpe9zMVvLix4S2FiQSJ99RIkNvhHomNO9uL3NhbHQ=

    Because a random salt is generated, the output of encodePassword is
    different every time you call it.

    >>> manager.encodePassword(password) != manager.encodePassword(password)
    True

    The password manager should be able to cope with unicode strings for input:

    >>> passwd = 'foobar\u2211' # sigma-sign.
    >>> manager.checkPassword(manager.encodePassword(passwd), passwd)
    True
    >>> manager.checkPassword(manager.encodePassword(passwd).decode(), passwd)
    True

    The manager only claims to implement SSHA512 encodings, anything not starting
    with the string {SSHA512} returns False:

    >>> manager.match('{MD5}someotherhash')
    False

    An older version of this manager used the urlsafe variant of the base64
    encoding (replacing / and + characters with _ and - respectively). Hashes
    encoded with the old manager are still supported:

    >>> encoded = '{SSHA512}E491yrR9AdCoE7rbOPYS3EZgSuZpVE65AD9xko08s6floNesY/Zpe9zMVvLix4S2FiQSJ99RIkNvhHomNO9uL3NhbHQ='
    >>> manager.checkPassword(encoded, 'secret')
    True


PBKDF2 password manager
-----------------------

The first manager is using PBKDF2_HMAC encrypted passwords; it's an implementation of the
PBKDF2 key derivation function using HMAC as a pseudorandom function:

    >>> from zope.interface.verify import verifyObject
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from pyams_security.password import PBKDF2PasswordManager

    >>> manager = PBKDF2PasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = "right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password, salt="")
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {PBKDF2}0P7toEokG2hpyVzih/AVCUyTnvPwchSazUxVmZUUUKy0elXtcvJ+eIAjr2gbWvxTzsTegfxE2305SbkNFMW0vw==

    >>> manager.match(encoded)
    True
    >>> manager.match(encoded.decode())
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + "wrong")
    False

    Our password manager generates the same value when seeded with the
    same salt, so we can be sure, our output is compatible with
    standard LDAP tools that also use SSHA:

    >>> from base64 import standard_b64decode
    >>> salt = standard_b64decode('ja/vZQ==')
    >>> password = 'secret'
    >>> encoded = manager.encodePassword(password, salt)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {PBKDF2}Lh1MYkcYvoSbu07KHD6fpkgql5fta0s0hvgZruXIOZhnjVZU9pTPtokuiku/ZbSdbluwlJxcYb56YkoHm+5gc42v72U=

    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + "wrong")
    False

    We can also pass a salt that is a text string:

    >>> salt = 'salt'
    >>> password = 'secret'
    >>> encoded = manager.encodePassword(password, salt)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {PBKDF2}N0XkgsbgreNdoQE555cVf0pdpmna19XaiO+H5HRxzEftlBx61hjoJzBPCD+HB/ErfP3V9Im3gvEMwmnjwI1ZrnNhbHQ=

    Because a random salt is generated, the output of encodePassword is
    different every time you call it.

    >>> manager.encodePassword(password) != manager.encodePassword(password)
    True

    The password manager should be able to cope with unicode strings for input:

    >>> passwd = 'foobar\u2211' # sigma-sign.
    >>> manager.checkPassword(manager.encodePassword(passwd), passwd)
    True
    >>> manager.checkPassword(manager.encodePassword(passwd).decode(), passwd)
    True

    The manager only claims to implement SSHA512 encodings, anything not starting
    with the string {PBKDF2} returns False:

    >>> manager.match('{MD5}someotherhash')
    False

    An older version of this manager used the urlsafe variant of the base64
    encoding (replacing / and + characters with _ and - respectively). Hashes
    encoded with the old manager are still supported:

    >>> encoded = '{PBKDF2}N0XkgsbgreNdoQE555cVf0pdpmna19XaiO+H5HRxzEftlBx61hjoJzBPCD+HB/ErfP3V9Im3gvEMwmnjwI1ZrnNhbHQ='
    >>> manager.checkPassword(encoded, 'secret')
    True


Tests cleanup:

    >>> tearDown()
