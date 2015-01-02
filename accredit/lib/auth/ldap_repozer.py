'''
This repoze.who plugin is based/influenced on repoze.who.plugins.ldap
and assumes that the user is identified as an LDAP entry.
'''

import zope.interface
import zope.interface.verify
import logging
import ldap
import ldap.dn
import base64
import importlib

from repoze.who.interfaces import (IAuthenticator, IMetadataProvider)

from paste.deploy.converters import asbool

from accredit.interfaces import ILoginNameMapper
from accredit.lib.class_loader import (load_class, instantiate_class)

log1 = logging.getLogger(__name__)

#
# Authenticators
#

class LdapAuthenticatorPlugin(object):
    '''
    Provides authentication against an LDAP directory
    '''

    zope.interface.implements(IAuthenticator)

    def __init__(self, ldap_url,
        parent_dn = '', naming_attribute = '',
        ret_style = 'dn',
        login_mapper = None,
        start_tls = False):

        """
        Authenticates a user by trying to bind to his DN.

        @param parent_dn: The parent LDAP entry under which the user's DN is supposed to be.
        @param naming_attribute: The attribute used to provide the RDN

        """

        log1.info('Setting up authenticator: %s' %(self))

        self.ldap_url  = str(ldap_url)
        self.parent_dn = str(parent_dn)
        self.naming_attribute = str(naming_attribute)
        self.ret_style = ret_style
        self.login_mapper = login_mapper
        self.start_tls = start_tls

        if not ldap_url:
            raise ValueError('An LDAP url must be specified')

        # canonicalize parent DN
        try:
            dn_parts = ldap.dn.explode_dn(self.parent_dn)
            self.parent_dn = ','.join(dn_parts)
        except ldap.DECODING_ERROR, ex:
            raise ValueError('The parent_dn (%s) is not valid' %(self.parent_dn))

        return

    def _get_credentials(self, environ, identity):
        '''
        Build the user's DN based on the supplied identity from repoze.who
        (most probably coming from a form-based challenger)
        '''

        # get the login_name as it was entered by the user
        login_name = identity.get('login', '').encode('utf-8')

        # the login_name may be mapped to a different name
        name = self.login_mapper.to_name(login_name) if self.login_mapper else login_name

        # get the password as entered by the user
        password = identity.get('password', '').encode('utf-8')

        if not (len(name) > 0 and len(password) > 0):
            # do not allow anonymous logins
            return (None,None)
        else:
            # seems ok, build the corresponding user's DN
            user_rdn = "%s=%s" %(self.naming_attribute, name)
            user_dn = user_rdn + ',' + self.parent_dn
            return (user_dn, password)

    def _setup_connection(self, user_dn, user_pass):
        '''
        Connect and bind to the LDAP server using the ini-provided credentials.

        @return: a usable connection object or None.
        '''

        if (not user_dn) or (not len(user_dn)):
            return None

        ldap_conn = ldap.initialize(self.ldap_url)

        if self.start_tls:
            try:
                ldap_conn.start_tls_s()
                log1.info ('The connection is now speaking TLS')
            except ldap.LDAPError, ex:
                raise ValueError('Cannot upgrade the connection (TLS): %s' %(ex))

        try:
            ldap_conn.bind_s(user_dn, user_pass)
            log1.info ('Connection to %s is bound to DN: %s' %(self.ldap_url, user_dn))
        except ldap.LDAPError, ex:
            log1.info ("Failed to bind to %s with supplied credentials ((%s),%s): %s" %(
                self.ldap_url, user_dn, user_pass, ex))
            ldap_conn = None

        return ldap_conn

    #
    # IAuthenticator interface
    #

    def authenticate(self, environ, identity):
        """Return the naming identifier (the DN) of the user to be authenticated.

        @return: The naming identifier, if the credentials were valid.
        @rtype: C{unicode} or C{None}

        """

        user_dn, user_pass = self._get_credentials(environ, identity)

        log1.info ('Trying to authenticate (i.e bind) with ((%s),%s)' %(user_dn,user_pass))

        conn = self._setup_connection(user_dn, user_pass)

        if conn:
            # The credentials were valid
            log1.info (' ** bind was successfull')
            userdata = identity.get('userdata', '')
            if self.ret_style == 'dn':
                return user_dn
            else:
                identity['userdata'] = userdata + '<dn:%s>' % base64.b64encode(user_dn)
                return identity['login']
        else:
            # Invalid credentials
            log1.info (' ** bind has failed')
            return None

def make_authenticator_plugin(ldap_connection,
        parent_dn = '',
        naming_attribute = 'uid',
        ret_style = 'dn',
        login_to_name = None,
        start_tls = False):
    if login_to_name:
        # Try to instantiate a login_mapper class
        login_mapper = instantiate_class(login_to_name)
        zope.interface.verify.verifyObject(ILoginNameMapper, login_mapper)
        log1.info ('Using login_to_name mapper: %s' %(login_mapper))
    return LdapAuthenticatorPlugin(ldap_url = ldap_connection,
        parent_dn = parent_dn,
        naming_attribute = naming_attribute,
        ret_style = ret_style,
        login_mapper = login_mapper,
        start_tls = asbool(start_tls));

#
# Metadata providers
#

class LdapMetadataPlugin(object):
    '''
    Loads the user metadata (attributes and optionally group membership)
    for an authenticated user.
    '''

    zope.interface.implements(IMetadataProvider)

    def __init__(self, ldap_url,
        bind_dn = '', bind_pass = '',
        start_tls = False,
        attributes = None):

        """
        Fetch metadata for an authenticated user.

        @param bind_dn: Connect to the LDAP endpoint and bind as this DN.
        @param bind_pass: The password for the bind operation.
        @param attributes: A list of user attributes to be fetched.

        """

        log1.info ('Setting up metadata-provider: %s' %(self))

        self.ldap_url  = str(ldap_url)
        self.bind_dn   = str(bind_dn)
        self.bind_pass = bind_pass
        self.start_tls = start_tls

        if not ldap_url:
            raise ValueError('An LDAP url must be specified')

        # canonicalize bind DN
        try:
            dn_parts = ldap.dn.explode_dn(self.bind_dn)
            self.bind_dn = ','.join(dn_parts)
        except ldap.DECODING_ERROR, ex:
            raise ValueError('The bind_dn (%s) is not valid' %(self.bind_dn))

        # canonicalize list of requested attributes
        self.attributes = None
        if isinstance(attributes, list):
            self.attributes = attributes
        elif isinstance(attributes, str):
            self.attributes = map(lambda v: v.strip(), attributes.split(','))

        return

    def _setup_connection(self):
        '''
        Connect and bind to the LDAP server using the ini-provided credentials.

        @return: a usable connection object.
        '''

        # Todo: maybe a Queue.Queue-based pool of connections?

        ldap_conn = ldap.initialize(self.ldap_url)

        if self.start_tls:
            try:
                ldap_conn.start_tls_s()
                log1.info ('The connection is now speaking TLS')
            except ldap.LDAPError, ex:
                raise ValueError('Cannot upgrade the connection (TLS): %s' %(ex))

        if self.bind_dn:
            try:
                ldap_conn.bind_s(self.bind_dn, self.bind_pass)
                log1.info ('Connection to %s is bound to DN: %s' %(self.ldap_url, self.bind_dn))
            except ldap.LDAPError, ex:
                raise ValueError("Cannot bind to %s with supplied credentials (%s,%s): %s" %(
                    self.ldap_url, self.bind_dn, self.bind_pass, ex))

        return ldap_conn

    #
    # IMetadataProvider interface
    #

    def add_metadata(self, environ, identity):
        """
        Add metadata about the authenticated user to the identity.
        It provides a set of desired attributes from the user's DN

        It modifies the C{identity} dictionary by adding/replacing a 'metadata' key.

        @param environ: The WSGI environment.
        @param identity: The repoze.who's identity dictionary.

        """

        user_dn = identity.get('repoze.who.userid')

        identity['metadata'] = {}

        ldap_conn = self._setup_connection()

        # Retrieve user attributes

        try:
            r = ldap_conn.search_s(user_dn, ldap.SCOPE_BASE, '(objectClass=*)', self.attributes)
        except ldap.LDAPError, ex:
            log1.warn('add_metadata(): userid="%s": %s' % (user_dn, ex))
        else:
            log1.info ('Loaded metadata for DN="%s"' %(user_dn))
            identity['metadata'].update(r[0][1])
        finally:
            ldap_conn.unbind_s()

def make_metadata_plugin(ldap_connection,
        bind_dn = '',
        bind_pass = '',
        start_tls = False,
        attributes = None):
    return LdapMetadataPlugin(ldap_url = ldap_connection,
        bind_dn = bind_dn,
        bind_pass = bind_pass,
        start_tls = asbool(start_tls),
        attributes = attributes);


