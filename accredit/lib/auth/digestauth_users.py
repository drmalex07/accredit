import logging
log1 = logging.getLogger(__name__)

from hashlib import md5

users = [
    # tuples of the form (username, realm, password)
    ('lalakis', 'accredit', 'l@lakis'),
    ('whatif', 'accredit', 'whatif'),
]

def get_digested_password(username, realm):
    ''' A example implementation of the 'get_pwdhash' callback needed
    by repoze.who.plugins.digestauth authenticator
    '''
    log1.info ('Retrieving password of (%s,%s)' %(username, realm))
    matching_users = filter (lambda t: t[0] == username and t[1] == realm, users);
    if matching_users:
        t = matching_users[0]
        return md5('%s:%s:%s' %(username, realm, t[2])).hexdigest()
    else:
        return ''
