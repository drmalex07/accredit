import logging
from decorator import decorator

from pylons import request, tmpl_context as c
from pylons import app_globals as g
from pylons.controllers.util import abort

from accredit.lib.decorators import context_sensitive_memoizer
from accredit.lib.auth.identity import Identity

log1 = logging.getLogger(__name__)

def is_authenticated():
    ''' Returns whether the client is authenticated '''
    i = get_identity()
    return i is not None

@context_sensitive_memoizer
def get_identity():
    ''' Returns an instance of an Identity for an authenticated client (via repoze.who).
    The uid is extracted from the associated repoze.who metadata.
    '''
    who_metadata = get_who_metadata()
    if (not isinstance(who_metadata,dict)) or (not who_metadata.has_key(g.op_uid_key)):
        return None

    uid = who_metadata[g.op_uid_key]
    uid = str(uid[0]) if isinstance(uid,list) else str(uid)
    identity = None
    try:
        identity = Identity(uid=uid)
    except ValueError as ex:
        log1.warning('Cannot build identity for uid="%s": %s' %(uid, str(ex)))
        identity = None
    return identity

@context_sensitive_memoizer
def get_who_metadata():
    who_identity = request.environ.get('repoze.who.identity')
    if not isinstance(who_identity,dict):
        return None
    who_metadata = who_identity.get('metadata')
    return who_metadata

def get_who_identity():
    who_identity = request.environ.get('repoze.who.identity')
    if not isinstance(who_identity,dict):
        return None
    return who_identity

@decorator
def authenticated(fn, *args, **kwargs):
    """ Decorator that will use Pylons' abort method to trigger the repoze.who
        middleware that this request needs to be authenticated. """
    if not is_authenticated():
        abort(401)
    return fn(*args, **kwargs)

