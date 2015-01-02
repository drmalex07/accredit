""" The application's Globals object
"""

import logging
import os
import re
import threading
import zope.interface
import zope.interface.verify

from bidict import bidict

from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options

from routes.util import url_for

from paste.deploy.converters import aslist, asbool, asint

import openid.server.server
import openid.store.memstore
import openid.store.filestore

import accredit.lib.auth.trust_policy as trust_policy

from accredit.lib.class_loader import instantiate_class
from accredit.interfaces import IAxAttributeComposer

log1 = logging.getLogger(__name__)

class Globals(object):
    """Globals acts as a container for objects available throughout the
    life of the application

    """

    def __init__(self, config):
        """One instance of Globals is created during application
        initialization and is available during requests via the
        'app_globals' variable

        """

        # Setup cache manager 

        self.cache = CacheManager(**parse_cache_config_options(config))

        # Setup common global settings 

        self.site_name = config.get('site.name', 'accredit')

        self.site_lang = config.get('site.lang', 'en')

        #
        # Create the openid-provider (OP) related objects
        #

        op_store_backend = config.get('openid_provider.store.backend', 'file')

        self.op_store = None
        if op_store_backend == 'redis':
            import openidredis
            self.op_store = openidredis.RedisStore(
                host = config.get('openid_provider.store.backend.redis.host', 'localhost'),
                port = asint(config.get('openid_provider.store.backend.redis.port', 6379)),
                db = asint(config.get('openid_provider.store.backend.redis.db', 0)),
                key_prefix = config.get('openid_provider.store.backend.redis.key_prefix', 'openid')
            )
            log1.info('Created Redis-based store for openid server at %s:%s db=%d prefix=%s',
                self.op_store.host, self.op_store.port, self.op_store.db, self.op_store.key_prefix)
        else:
            data_dir = config.get('openid_provider.store.backend.file.data_dir')
            if not data_dir:
                data_dir = config.get('openid_provider.data_dir')
            self.op_store = openid.store.filestore.FileOpenIDStore(data_dir);
            log1.info('Created file-based store for openid server at %s', data_dir)


        self.op_endpoint = url_for('openid-provider',
            host = config.get('server_name'),
            protocol = 'https'
        )

        # Fixme: Any thread-safety issues with op_server's state ??

        self.op_server = None
        if asbool(config.get('openid_provider.force_synchronized', False)):
            self.op_server = SynchronizedOpServer(self.op_store, op_endpoint=self.op_endpoint)
        else:
            self.op_server = OpServer(self.op_store, op_endpoint=self.op_endpoint)
        log1.info ('Created a global instance of %s' %(type(self.op_server)))

        # Setup trust registry

        registry_backend = config.get('openid_provider.trust.backend', 'memory')
        ky = 'openid_provider.trust.backend.%s.' %(registry_backend)
        registry_backend_args = { k[len(ky):]: config[k] for k in
            filter(lambda g: g.startswith(ky), config.keys()) }
        self.op_trust_registry = trust_policy.create_registry(registry_backend, **registry_backend_args)
        log1.info ('Created a trust-policy registry as %s' %(self.op_trust_registry))

        # Setup exported SReg attributes 

        uid_attr = config.get('openid_provider.identity.uid', 'metadata:uid')
        if not uid_attr.startswith('metadata:'):
            raise ValueError('The openid_provider.identity.uid value is malformed')
        self.op_uid_key = uid_attr[len('metadata:'):]

        self.op_sreg_attrs = frozenset(aslist(
            config.get('openid_provider.sreg.attrs'), sep=',', strip=True))
        self.op_sreg_attr_map = dict()
        for a in self.op_sreg_attrs:
            y = config.get("openid_provider.sreg.attr.%s" %(a))
            if y and y.startswith('metadata:'):
                self.op_sreg_attr_map[a] = y[len('metadata:'):]

        # Setup exported AX attributes 

        self.op_ax_attrs = frozenset(aslist(
            config.get('openid_provider.ax.attrs'), sep=',', strip=True))
        self.op_ax_attr_map = dict()
        self.op_ax_attr_types = bidict() # bidirectional mapping
        self.op_ax_attr_descriptions = dict()
        for j,a in enumerate(self.op_ax_attrs):
            ky = 'openid_provider.ax.attr.%s' %(a)
            # a. Setup mapping for this AX attribute (how is it calculated)
            y  = config.get(ky)
            if y:
                if y.startswith('metadata:'):
                    # This AX attribute is retrieved directly from repoze.who metadata
                    metadata_key = y[len('metadata:'):]
                    self.op_ax_attr_map[a] = metadata_key
                elif y.startswith('callback:'):
                    # This AX attribute is calculated by a callback on repoze.who metadata 
                    callback_args = { k1: config.get('%s.callback.args.%s' %(ky, k1)) for k1 in
                        aslist(config.get('%s.callback.args' %(ky)), sep=',', strip=True) }
                    callback = instantiate_class(y[len('callback:'):], **callback_args)
                    zope.interface.verify.verifyObject(IAxAttributeComposer, callback)
                    self.op_ax_attr_map[a] = callback
                log1.info ('Added an exportable AX attribute %s mapped as %s' %(repr(a),
                    repr(self.op_ax_attr_map[a])))
            # b. Setup type_uri and an alias for this AX attribute
            y = config.get('%s.type' %(ky))
            if y and y.startswith("http://"):
                self.op_ax_attr_types[a] = y.lower()
            else:
                self.op_ax_attr_types[a] = url_for('openid-ax-schema',
                    typename='anon-%d'%(j), host=config.get('server_name'), protocol='http')
            # c. Setup a description for this AX attribute (if provided)
            y = config.get('%s.description' %(ky))
            if y:
                self.op_ax_attr_descriptions[a] = y.strip().decode('utf-8')

        # Setup global trust-policy rules: whitelisted/blacklisted RPs

        self.op_trust_whitelisted_realms = {}
        re_whitelist_rule = re.compile('openid_provider[.]trust[.]whitelisted_realms[.]([0-9a-z]+)$')
        for k in filter(lambda y: re_whitelist_rule.match(y), config.keys()):
            realm = str(config.get(k)).strip(' /') + '/'
            self.op_trust_whitelisted_realms[k] = realm
            self.op_trust_registry.update('global', realm, trust_policy.Policy('always',
                frozenset(self.op_sreg_attrs), frozenset(self.op_ax_attrs)
            ))
            log1.info ('Whitelisted realm: %s' %(realm))

        self.op_trust_blacklisted_realms = {}
        re_blacklist_rule = re.compile('openid_provider[.]trust[.]blacklisted_realms[.]([0-9a-z]+)$')
        for k in filter(lambda y: re_blacklist_rule.match(y), config.keys()):
            realm = str(config.get(k)).strip(' /') + '/'
            self.op_trust_blacklisted_realms[k] = realm
            self.op_trust_registry.update('global', realm, trust_policy.Policy('never', None, None))
            log1.info ('Blacklisted realm: %s' %(realm))

        #
        # Todo Setup AccountManager 
        #

        self.account_manager = None 


class OpServer(openid.server.server.Server):
    pass

class SynchronizedOpServer(openid.server.server.Server):
    """
    This class overrides certain Server methods and forces them to run
    synchronized - by using simple recursive locks (threading.RLock).

    Not 100% sure if this is actually required since the python-openid docs
    state that the openid.Server maintains all it's state inside the object
    that implements the openid.Store interface. We are using the FileStore
    (which claims to be thread-safe), so theoretically everything should be ok.
    """

    def __init__(self, *args, **kwargs):
        openid.server.server.Server.__init__(self, *args, **kwargs)
        self._lock = threading.RLock()
        return

    def decodeRequest(self, query):
        openid_req = None
        with self._lock:
            openid_req = openid.server.server.Server.decodeRequest(self, query)
        return openid_req

    def encodeResponse(self, openid_res):
        r = None
        with self._lock:
            r = openid.server.server.Server.encodeResponse(self, openid_res)
        return r

    def handleRequest(self, openid_req):
        openid_res = None
        with self._lock:
            openid_res = openid.server.server.Server.handleRequest(self, openid_req)
        return openid_res


