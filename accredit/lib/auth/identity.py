import re
from urlparse import urlparse

from pylons import url
from pylons import config

class Identity(object):

    re_uid_validator = re.compile('^\w[\w\d]*([-.][\w\d]+)*$', re.UNICODE)

    def __init__(self, uid=None, uri=None):
        if uid and uri:
            raise ValueError('The "uid" and "uri" arguments are mutually exclusive')
        elif uid:
            if uid == '*':
                # a wildcard that selects the logged-in user
                self.uid = '*'
                self.uri = url('openid-identity-select',
                    uid='*', host=config['server_name'], protocol='https')
            elif self.re_uid_validator.match(uid):
                # a normal user's identity
                self.uid = uid
                self.uri = url('openid-identity',
                    uid=uid, host=config['server_name'], protocol='https')
            else:
                raise ValueError('The provided uid is malformed')
        elif uri:
            uri_parts = urlparse(uri)
            if uri_parts.netloc != config['server_name']:
                raise ValueError('The provided uri does not match the domain name (%s)' %(uri_parts.netloc))
            routes_mapper = config['routes.map']
            r = routes_mapper.match(uri_parts.path)
            if (not r) or (not isinstance(r,dict)) or (not r.get('controller') == 'openid_provider') or (not r.has_key('uid')):
                raise ValueError('The  provided uri does not match an identity URI')
            # ok, seems well-formed
            self.uid = r['uid']
            self.uri = uri
        else:
            raise ValueError('One of the "uid" or "uri" arguments must be provided')

    def __str__(self):
        return "<Identity uid=%s>" %(self.uid)

    def get_uri(self):
        return self.uri

    def get_uid(self):
        return self.uid

    def is_specified(self):
        return self.uid != '*'

    def __eq__(self, other):
        return \
            (self.uid == '*') or (other.uid == '*') or \
            (self.uid == other.uid)

