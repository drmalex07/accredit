import logging
import time
import datetime
import threading
import collections
import copy
import pickle
import redis

from collections import namedtuple

from accredit.lib.auth.identity import Identity

log1 = logging.getLogger(__name__)

# Policy is a class that describes a trust-policy.
# It is defined as namedtuple and it is immutable, so multiple threads can hold a 
# reference to the same instance

Policy = namedtuple('Policy',[
    'allow',                 # an str, one of ["once", "always", "never"]
    'exported_sreg_attrs',   # a frozenset of the exported SReg attributes
    'exported_ax_attrs'      # a frozenset of the exported AX attributes (as type URIs)
    ], verbose=False)

class BaseRegistry(object):

    def get(self, identity, trust_root):
        ''' Retrieve the policy for (identity,trust_root).
        If identity is 'global', then we search for a global policy defined for trust_root
        else, we search for a per-user policy (and identity should be an instance of Identity).
        '''
        return None

    def get_by_identity(self, identity):
        ''' Retrieve all policy objects associated with a given user identity. '''
        return None

    def update(self, identity, trust_root, policy, ttl_seconds=None):
        ''' Update (or add) the policy for (identity,trust_root).
        If identity is 'global', then we update the global policy for trust_root,
        else we update the per-user policy (and identity should be an instance of Identity)
        '''
        return

    def remove(self, identity, trust_root):
        ''' Discard the policy for (identity,trust_root).
        If identity is 'global', then we discard the global policy for trust_root
        '''
        return None

    def remove_by_identity(self, identity):
        ''' Discard all policies associated with a given user identity.
        '''
        return None

    def dumps(self):
        ''' Provide a textual (e.g. python code?) dump for this registry. '''
        return

    def match(self, identity, trust_root):
        ''' Find a matching (applicable) policy for the given pair of (identity,trust_root),
        by trying the following (in this order):
         - examine if a specific (per-user) rule exists.
         - examine if a global failback rule exists for the given trust_root (realm).
        '''
        policy = self.get(identity,trust_root)
        if not policy:
            policy = self.get('global',trust_root)
        return policy

class MemoryRegistry(BaseRegistry):
    ''' A multithread-safe and expiry-aware registry (dictionary) of Policy
    objects keyed to the pair (<identity>,<trust-root>).
    '''

    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()

    def get(self, identity, trust_root):
        if str(identity) == 'global':
            return self._get_global_policy(trust_root)
        else:
            return self._get_user_policy(identity,trust_root)

    def _get_global_policy(self, trust_root):
        k = (None, str(trust_root))
        policy = None
        with self._lock:
            policy,unused_timestamp = self._items.get(k, (None,None))
        return policy

    def _get_user_policy(self, identity, trust_root):
        assert (isinstance(identity, Identity))
        k = (identity.uid, str(trust_root))
        policy,expiry_timestamp = (None,None)
        with self._lock:
            policy,expiry_timestamp = self._items.get(k, (None,None))
            # check if trust is expired
            if expiry_timestamp:
                now_timestamp = time.time()
                if expiry_timestamp < now_timestamp:
                    self._items.pop(k)
                    policy = None
            # check if this policy is to be used once
            if policy and policy.allow == 'once':
                self._items.pop(k)
        # release lock and return
        return policy

    def get_by_identity(self, identity):
        assert (isinstance(identity, Identity))
        policies = {}
        with self._lock:
            for k,v in self._items.items():
                if k[0] == identity.uid:
                    policies[k[1]] = v[0]
        return policies

    def update(self, identity, trust_root, policy, ttl_seconds=None):
        if str(identity) == 'global':
            return self._update_global_policy(trust_root, policy)
        else:
            return self._update_user_policy(identity, trust_root, policy, ttl_seconds)

    def _update_user_policy(self, identity, trust_root, policy, ttl_seconds=None):
        assert (isinstance(identity, Identity) and isinstance(policy, Policy))
        k = (identity.uid, str(trust_root))
        expiry_timestamp = (time.time() + float(ttl_seconds)) if ttl_seconds else None
        with self._lock:
            self._items[k] = (policy,expiry_timestamp)
        return policy

    def _update_global_policy(self, trust_root, policy):
        assert (isinstance(policy, Policy))
        k = (None, str(trust_root))
        with self._lock:
            self._items[k] = (policy,None)
        return policy

    def remove(self, identity, trust_root):
        if str(identity) == 'global':
            return self._remove_global_policy(trust_root)
        else:
            return self._remove_user_policy(identity, trust_root)

    def _remove_global_policy(self, trust_root):
        k = (None, trust_root)
        t = (None,None)
        with self._lock:
            t = self._items.pop(k,t)
        return k if t[0] else None

    def _remove_user_policy(self, identity, trust_root):
        assert (isinstance(identity, Identity))
        k = (identity.uid, trust_root)
        t = (None,None)
        with self._lock:
            t = self._items.pop(k,t)
        return k if t[0] else None

    def remove_by_identity(self, identity):
        assert (isinstance(identity, Identity))
        remove_keys = []
        with self._lock:
            remove_keys = filter(lambda y: y[0] == identity.uid, self._items.keys())
            for k in remove_keys:
                self._items.pop(k)
        return remove_keys

    def dumps(self):
        from datetime import datetime
        indent = ' '*4;
        with self._lock:
            keys = self._items.keys()
            output = "{\n";
            for k in keys:
                policy,timestamp = self._items.get(k, (None, None))
                expiry_date = datetime.fromtimestamp(timestamp).isoformat() if timestamp else '<infinity>'
                output += "%s(\"%s\", \"%s\"): (\"expires: %s\",\n%s%s)\n" %(
                    indent,(k[0] if k[0] else '<global>'), k[1],
                    expiry_date, indent*2,
                    repr(policy)
                )
        output += "}"
        return output

class RedisRegistry(BaseRegistry):

    def __init__(self, host='localhost', port=6379, db=0, key_prefix='trust:'):
        self._store = redis.Redis(host=host, port=int(port), db=int(db))
        self._key_prefix = key_prefix
        log1.debug('Connected to a Redis instance at %s:%s db=%s prefix=%s' %(
            host, port, db, key_prefix))

    def get(self, identity, trust_root):
        if str(identity) == 'global':
            return self._get_global_policy(trust_root)
        else:
            return self._get_user_policy(identity,trust_root)

    def _get_global_policy(self, trust_root):
        k = self._key_prefix + "global::%s" %(str(trust_root))
        policy = None
        p = self._store.get(k)
        if p:
            policy = pickle.loads(p)
        return policy

    def _get_user_policy(self, identity, trust_root):
        assert (isinstance(identity, Identity))
        k = self._key_prefix + "user::%s::%s" %(identity.uid, str(trust_root))
        policy = None
        p = self._store.get(k)
        if p:
            policy = pickle.loads(p)
            if policy and policy.allow == 'once':
                self._store.delete(k)
        return policy

    def get_by_identity(self, identity):
        assert (isinstance(identity, Identity))
        policies = {}
        key_prefix = self._key_prefix + "user::%s::" %(identity.uid)
        keys = self._store.keys(key_prefix+'*')
        if len(keys):
            values = self._store.mget(*keys)
            for k,v in zip(keys,values):
                policies[k[len(key_prefix):]] = pickle.loads(v)
        return policies

    def update(self, identity, trust_root, policy, ttl_seconds=None):
        if str(identity) == 'global':
            return self._update_global_policy(trust_root, policy)
        else:
            return self._update_user_policy(identity, trust_root, policy, ttl_seconds)

    def _update_user_policy(self, identity, trust_root, policy, ttl_seconds=None):
        assert (isinstance(identity, Identity) and isinstance(policy, Policy))
        k = self._key_prefix + "user::%s::%s" %(identity.uid, str(trust_root))
        p = pickle.dumps(policy)
        self._store.setex(k,p,ttl_seconds)
        return policy

    def _update_global_policy(self, trust_root, policy):
        assert (isinstance(policy, Policy))
        k = self._key_prefix + "global::%s" %(str(trust_root))
        p = pickle.dumps(policy)
        self._store.set(k,p)
        return policy

    def remove(self, identity, trust_root):
        if str(identity) == 'global':
            return self._remove_global_policy(trust_root)
        else:
            return self._remove_user_policy(identity, trust_root)

    def _remove_global_policy(self, trust_root):
        k = self._key_prefix + "global::%s" %(str(trust_root))
        removed = self._store.delete(k)
        return k if removed else None

    def _remove_user_policy(self, identity, trust_root):
        assert (isinstance(identity, Identity))
        k = self._key_prefix + "user::%s::%s" %(identity.uid, str(trust_root))
        removed = self._store.delete(k)
        return k if removed else None

    def remove_by_identity(self, identity):
        assert (isinstance(identity, Identity))
        key_prefix = self._key_prefix + "user::%s::" %(identity.uid)
        keys = self._store.keys(key_prefix+'*')
        pipe = self._store.pipeline()
        for k in keys:
            pipe.delete(k)
        res = pipe.execute()
        assert (len(res) == len(keys))
        return keys

    def dumps(self):
        from datetime import datetime
        indent = ' '*4;
        now_timestamp = int(datetime.now().strftime('%s'))
        output = "{\n";
        keys = \
            self._store.keys(self._key_prefix + 'global::*') +\
            self._store.keys(self._key_prefix + 'user::*')
        if len(keys):
            vals = self._store.mget(*keys)
            for k,p in zip(keys,vals):
                try:
                    policy = pickle.loads(p)
                    ttl = self._store.ttl(k)
                    expiry_date = datetime.fromtimestamp(now_timestamp + ttl).isoformat() if ttl else '<infinity>'
                    output += "%s\"%s\": (\"expires: %s\",\n%s%s)" %(indent, k, expiry_date, indent*2, repr(policy))
                    output += "\n"
                except:
                    pass
        output += "}"
        return output

def create_registry(backend, **kwargs):
    r = None
    if backend == 'redis':
        r = RedisRegistry(**kwargs)
    elif backend == 'memory':
        r = MemoryRegistry(**kwargs)
    else:
        raise ValueError('Cannot recognize registry backend "%s"' %(backend))
    return r

Registry = MemoryRegistry
