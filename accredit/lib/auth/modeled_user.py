from zope.interface import implements

from repoze.who.interfaces import (IAuthenticator, IMetadataProvider)
from repoze.who.utils import resolveDotted

import sqlalchemy as sqla
import sqlalchemy.orm
import sqlalchemy.orm.exc

import json

import accredit.model as model

import logging
log1 = logging.getLogger(__name__)

class ModeledUserPlugin(object):

    implements(IAuthenticator, IMetadataProvider)

    def __init__(self):
        self.db_session = model.Session()

    #
    # IAuthenticator interface
    #

    def authenticate(self, environ, identity):
        '''
        Expects param `identity` to be a dict of posted values for ('login', 'password')
        Return a non-empty username if credentials are valid '''
        try:
            login    = identity['login']
            password = identity['password']
        except KeyError:
            return None

        log1.info (' ** Checking authn for user %s' %(login))

        try:
            matched_user = self.db_session.query(model.User).filter(model.User.username == login).one()
        except sqla.orm.exc.NoResultFound:
            return None

        if matched_user.check_password(password):
            return matched_user.username

        return None

    #
    # IMetadataProvider interface
    #

    def add_metadata(self, environ, identity):
        '''
        Provides arbitrary dict-based metadata for every authenticated request
        '''

        log1.info (' ** Adding metadata for identity %s' %(repr(identity.items())))

        username = identity['repoze.who.userid']

        user = self.db_session.query(model.User).filter(model.User.username == username).one()
        
        # The key 'userdata' expects a string (participates in signed auth_tkt cookie and is sent 
        # back to the client)
        # I dont see a reason to set it to something usefull ...
        #identity['userdata'] = 'ababoua'
        
        # Add some arbitrary data
        identity['extra'] = {
            'description': user.description,
            'boo': 'far',
        };

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))

def make_plugin():
    return ModeledUserPlugin()

