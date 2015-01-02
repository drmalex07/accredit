'''

An OpenID-Provider (OP) web interface, based on the python-openid module.

See more at:
  - http://openid.net/specs/openid-authentication-2_0.html  (OpenID specs)
  - http://www.theserverside.com/news/1364125/Using-OpenID
  - http://wiki.openid.net/w/page/12995171/Introduction
  - http://wiki.openid.net/w/page/12995200/OpenID%20Security%20Best%20Practices

'''

import logging
import re
import json
from base64 import b64encode, b64decode
from enum import Enum

from pylons import request, response, session, tmpl_context as c, url
from pylons.controllers.util import abort, redirect
from pylons import config
from pylons import app_globals as g
from pylons.i18n import (get_lang, set_lang, _)

import openid.server.server
import openid.consumer.discover
import openid.message
import openid.extensions.sreg
import openid.extensions.ax

from openid.server.server import (ENCODE_KVFORM, ENCODE_URL)
from openid.extensions.sreg import (SRegRequest, SRegResponse)
from openid.extensions.ax import (FetchRequest as AxFetchRequest, FetchResponse as AxFetchResponse)

import accredit.lib.helpers as h
import accredit.lib.auth.trust_policy as trust_policy

from accredit.lib.base import BaseController, render
from accredit.lib.auth.identity import Identity
from accredit.lib.auth.helpers import (is_authenticated, get_identity, get_who_identity, get_who_metadata)

log1 = logging.getLogger(__name__)

STATUS_STARTED   = 0b0001
STATUS_CANCELLED = 0b0010
STATUS_PENDING   = 0b0100

class OpenidProviderController(BaseController):

    def __before__(self):
        return

    def __after__(self):
        session.save()
        return

    def provide(self):
        openid_req = None
        openid_req_status = 0b0

        # Attempt to instantiate an openid-request by trying to
        # (a) parse the current request params
        # (b) resume a pending one (maybe cancelled) from a previous incomplete request

        try:
            openid_req = g.op_server.decodeRequest(request.params)
        except openid.server.server.ProtocolError, ex:
            self._render_openid_result(ex)

        if openid_req is None:
            # not an openid request: check if we have a pending incomplete one
            openid_req_status = session.get('openid_req_status', 0b0)
            if openid_req_status & STATUS_PENDING:
                openid_req = session['openid_req']
        else:
            # it seems we have received a new openid request: save it in session
            openid_req_status = STATUS_STARTED
            session['openid_req'] = openid_req
            session['openid_req_status'] = openid_req_status

        # Now, an openid-request must have been instantiated 

        log1.info ('provide(): Processing %s' %(repr(openid_req) if openid_req else '<none>'))

        if openid_req is None:
            # Nop
            return render('openid_provider/about.html')
        elif openid_req_status & STATUS_CANCELLED:
            # Cancel the pending request and clear the relevant session objects
            openid_res = openid_req.answer(False)
            log1.info(' *1* Discarding session data (cancelled)')
            ignored_data = [session.pop(k) for k in ['openid_req','openid_req_status']]
            return self._render_openid_result(openid_res)
        elif openid_req.mode in ['checkid_setup','checkid_immediate']:
            # Handle a valid checkid_setup request
            return self._handle_checkid_request(openid_req, openid_req_status)
        else:
            # Handle a valid non-checkid_* request using the default behaviour
            openid_res = g.op_server.handleRequest(openid_req)
            log1.info(' *3* Discarding session data (finished)')
            ignored_data = [session.pop(k,None) for k in ['openid_req','openid_req_status']]
            return self._render_openid_result(openid_res)

    def _render_openid_result(self, openid_res):
        ''' Render the openid response in an appropriate manner.
        Possibly, an HTML response that can be wrapped into an auto-submit form.
        '''

        try:
            r = g.op_server.encodeResponse(openid_res)
        except openid.server.server.EncodingError, ex:
            log1.error('Failed to encode result as HTTP response for %s' %(openid_res))
            msg = ex.response.encodeToKVForm()
            abort(500, 'Cannot encode HTTP response')

        response.status = "%s" %(r.code)

        # Cast header values explicitly to str (uwsgi is complaining about unicode values)
        # and update existing ones.
        response.headers.update({ str(k):str(v) for k,v in r.headers.items() })

        # Generate body based on the type of the openid response
        if r.body and len(r.body):
            if openid_res.whichEncoding() == ENCODE_KVFORM:
                return r.body
            else:
                c.trust_root = openid_res.request.trust_root
                return render('openid_provider/response-form.html', extra_vars = {
                    'body': h.Markup(r.body), # provide a safe markup stream
                })
        else:
            return ''

    def _handle_checkid_request(self, openid_req, openid_req_status):
        ''' Handle a checkid_* request, setup the response headers and
        return the response body (or abort).
        '''

        c.trust_root = trust_root = openid_req.trust_root

        expected_identity = None
        if openid_req.identity == openid.message.IDENTIFIER_SELECT:
            # Matches to the special value reserved to let the identifier to be selected in the OP side
            c.expected_identity = expected_identity = Identity(uid='*')
        else:
            # Expect a normal local identifier specified by the client
            c.expected_identity = expected_identity = Identity(uri=openid_req.identity)

        wants_immediate = (openid_req.mode == 'checkid_immediate')

        if is_authenticated():
            c.own_identity = own_identity = get_identity()
            if not (own_identity == expected_identity):
                log1.info(' *4* Discarding session data (other indentity)')
                ignored_data = [session.pop(k,None) for k in ['openid_req','openid_req_status']]
                if wants_immediate:
                    openid_res = openid_req.answer(False)
                    return self._render_openid_result(openid_res)
                else:
                    return render('openid_provider/other-identity.html')
            # At this point, an authenticated user requests to assert his own identity
            # Check if any extended (SReg or AX) attributes are requested
            sreg_req = SRegRequest.fromOpenIDRequest(openid_req)
            ax_req   = AxFetchRequest.fromOpenIDRequest(openid_req)
            # Examine trust-policy and decide where to go  
            policy = g.op_trust_registry.match(own_identity, trust_root)
            if not policy:
                # Cannot reject nor approve, act depending on the request mode: 
                # if in "checkid_setup" mode prompt user, else reply with a negative answer
                if wants_immediate:
                    openid_res = openid_req.answer(False)
                    return self._render_openid_result(openid_res)
                else:
                    session['openid_req_status'] = openid_req_status|STATUS_PENDING
                    self._add_sreg_template_vars(sreg_req)
                    self._add_ax_template_vars(ax_req)
                    return render('openid_provider/confirm.html')
            elif policy.allow in ['once','always']:
                # This RP is trusted: assert this request 
                # Note: The "identity" kw argument passed to answer() is meaningfull only
                # in the IDENTIFIER_SELECT case i.e when expected_identity.uid == '*'
                openid_res = openid_req.answer(True, identity=own_identity.uri)
                self._add_sreg_to_openid_result(openid_req, sreg_req, policy, openid_res)
                self._add_ax_to_openid_result(openid_req, ax_req, policy, openid_res)
                return self._render_openid_result(openid_res)
            else:
                # Behave as if it was "never" and reject this request
                openid_res = openid_req.answer(False)
                return self._render_openid_result(openid_res)
        else:
            # We have received an anonymous (non-authenticated) request
            if wants_immediate:
                openid_res = openid_req.answer(False)
                return self._render_openid_result(openid_res)
            else:
                # Redirect to a repoze.who login page
                session['openid_req_status'] = openid_req_status|STATUS_PENDING
                # Note: we dont abort(401), as suggested by repoze.who, because that 
                # causes a newly created session to be discarded!
                redirect(url('login-form', came_from=request.url))

    def _add_sreg_to_openid_result(self, openid_req, sreg_req, policy, openid_res):
        assert ((not sreg_req) or isinstance(sreg_req, SRegRequest))
        log1.debug('Adding SReg metadata to request %s ...' %(sreg_req))

        if not sreg_req:
            return

        requested_attrs = map(str, sreg_req.allRequestedFields())

        if isinstance(policy.exported_sreg_attrs,frozenset):
            attrs = (g.op_sreg_attrs & policy.exported_sreg_attrs & set(requested_attrs))
            if len(attrs):
                sreg_data = {}
                who_metadata = get_who_metadata()
                for a in attrs:
                    k = g.op_sreg_attr_map.get(a,a)
                    v = who_metadata.get(k)
                    if v:
                        v = ','.join(v) if isinstance(v,list) else str(v)
                        sreg_data[a] = v.decode('utf-8')
                if len(sreg_data):
                    sreg_res = SRegResponse.extractResponse(sreg_req, sreg_data)
                    openid_res.addExtension(sreg_res)
        else:
            log1.debug('No exported SReg attributes for %s' %(repr(openid_req)))
            pass
        return

    def _add_sreg_template_vars(self, sreg_req):
        assert ((sreg_req is None) or isinstance(sreg_req, SRegRequest))
        if sreg_req and sreg_req.wereFieldsRequested():
            c.sreg_is_requested = True
            c.sreg_required_fields = sreg_req.required
            c.sreg_optional_fields = sreg_req.optional
        else:
            c.sreg_is_requested = False
        return

    def _add_ax_to_openid_result(self, openid_req, ax_req, policy, openid_res):
        assert ((not ax_req) or isinstance(ax_req, AxFetchRequest))
        log1.debug('Adding AX metadata to request %s ...' %(ax_req))

        if not ax_req:
            # no AX attribute was requested
            return

        requested_attrs = map(lambda k: g.op_ax_attr_types.inv.get(k), ax_req.requested_attributes.keys())

        if isinstance(policy.exported_ax_attrs,frozenset):
            attrs = (g.op_ax_attrs & policy.exported_ax_attrs & set(requested_attrs))
            if len(attrs):
                who_metadata = get_who_metadata()
                ax_res = AxFetchResponse(ax_req)
                for a in attrs:
                    m = g.op_ax_attr_map.get(a,a)
                    t = g.op_ax_attr_types.get(a)
                    v = None
                    if isinstance(m,str):
                        v = who_metadata.get(m)
                    else:
                        # We assume that m is an object that provides IAxAttributeComposer
                        v = m.compose_from(who_metadata, a, t)
                    if v:
                        v = json.dumps(v)
                        ax_res.addValue(type_uri=t, value=b64encode(v))
                        log1.debug(' * Exported AX attr: %s -> %s' %(t,v))
                openid_res.addExtension(ax_res)
        return

    def _add_ax_template_vars(self, ax_req):
        assert ((ax_req is None) or isinstance(ax_req, AxFetchRequest))
        c.ax_is_requested = False
        if ax_req and len(ax_req.requested_attributes):
            c.ax_is_requested = True
            # Provide a list with requested AX attrs filtered by the ones supported
            # by this service (see .ini config for openid_provider.ax.attrs)
            c.ax_requested_attributes = []
            for v in ax_req.requested_attributes.values():
                # Filter attrs based on their type URIs
                a = g.op_ax_attr_types.inv.get(v.type_uri.lower()) # lookup type
                if a:
                    c.ax_requested_attributes.append((v.type_uri, a))
                else:
                    log1.info('Ignoring unknown AX attribute: %s' %(v.type_uri))
        return

    def confirm(self):
        own_identity = get_identity()

        if not own_identity:
            abort(401)

        if not request.POST:
            abort(405)

        trust_root = request.params['trust_root']

        if 'allow' in request.params:
            policy_type = 'always' if 'remember' in request.params else 'once'
            exported_sreg_attrs = frozenset(filter(
                lambda a: request.params.has_key('field-sreg-%s' %(a)), g.op_sreg_attrs))
            exported_ax_attrs = frozenset(filter(
                lambda a: request.params.has_key('field-ax-%s' %(a)), g.op_ax_attrs))
            g.op_trust_registry.update(own_identity, trust_root,
                policy = trust_policy.Policy(policy_type, exported_sreg_attrs, exported_ax_attrs),
                ttl_seconds = 3600)
        else:
            if 'remember' in request.params:
                g.op_trust_registry.update(own_identity, trust_root,
                    policy = trust_policy.Policy('never', None, None),
                    ttl_seconds = 6 * 3600)
            session['openid_req_status'] |= STATUS_CANCELLED

        # Now, resume with the openid transaction
        redirect(url('openid-provider'))

    def show_identity(self, uid):
        c.identity = Identity(uid=uid)
        return render('openid_provider/identity.html')

    def show_ax_schema(self, typename):
        ''' This is a dummy entry for schema defs of custom AX types '''
        abort(501, 'Not implemented')

    def show_yadis(self, uid):
        id1 = None
        try:
            id1 = Identity(uid=uid)
        except:
            abort(400, 'The user-id is malformed')
        response.headers['content-type'] = 'application/xml; charset=utf-8' # Fixme: xrds+xml
        return render('openid_provider/yadis.xml', extra_vars={
            'primary_type': openid.consumer.discover.OPENID_2_0_TYPE,
            'secondary_type': openid.consumer.discover.OPENID_1_0_TYPE,
            'server_uri': url('openid-provider', qualified=True, protocol='https'),
            'local_id': id1.uri if id1.is_specified() else openid.message.IDENTIFIER_SELECT,
        });

    def _debug_session(self):
        log1.debug ('session:')
        log1.debug (' * openid_req_status: %s' %(bin(session.get('openid_req_status'))))
        log1.debug (' * openid_req: %s' %(repr(session.get('openid_req'))))



