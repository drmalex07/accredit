import logging
import copy
import urlparse

from pylons import request, response, session, tmpl_context as c, url
from pylons.controllers.util import abort, redirect
from pylons.i18n import (get_lang, set_lang, _)
from pylons import app_globals as g

from accredit.lib.base import BaseController, render

import accredit.lib.helpers as h
import accredit.lib.auth.trust_policy as trust_policy

from accredit.lib.auth.identity import Identity
from accredit.lib.auth.helpers import (is_authenticated, authenticated, get_identity, get_who_identity, get_who_metadata)

log1 = logging.getLogger(__name__)

class UsersController(BaseController):

    def __before__(self):
        count_visits = session.get('count_visits', 0);
        c.count_visits = session['count_visits'] = count_visits +1;
        return

    def __after__(self):
        session.save()
        return

    #
    # login-related actions
    #

    def login_form(self):
        c.action = url(controller='users', action='login',
            came_from = request.params.get('came_from', '/'));
        c.reset_url = url(controller='users', action='reset_password_form');
        return render('users/login_redirecting_form.html');

    def login(self):
        ''' Not reached, intercepted by repoze.who to perform 'authenticate' and 'remember' duties '''
        pass

    def logged_in(self):
        ''' This action is called after the submission of a login request,
        either successfull or not.
        '''
        identity = request.environ.get("repoze.who.identity")
        came_from = request.params.get('came_from', '/')
        redirect_url = None
        if identity:
            # Performed a successfull login
            redirect_url = came_from
        else:
            # Failed login
            redirect_url = url(controller='users', action='login_form', came_from=came_from)
        redirect(redirect_url)
        return

    def logout(self):
        ''' Not reached, intercepted by repoze.who to perform 'forget' duties '''
        pass

    def logged_out(self):
        came_from = request.params.get('came_from')
        if came_from:
            redirect(came_from)
        return render('users/logged_out.html');

    def reset_password_form(self):
        return 'Hello reset-form'

    def reset_password(self):
        pass

    #
    # helpers
    #

    def _validate_csrf_token(self):
        if not (request.params.get(h.secure_form.token_key) == h.secure_form.authentication_token()):
            abort (403, detail=u'Not permitted (possible CSRF attack)')
        return True

    #
    # account-related actions
    #

    @authenticated
    def clear_all_trust(self):
        c.my_identity = my_identity = get_identity()
        if request.method == 'GET':
            c.action = url('users-clear-all-trust')
            c.csrf_token_field = h.secure_form.auth_token_hidden_field()
            return render('users/clear_all_trust.html')
        else:
            # Validate POST request
            self._validate_csrf_token()
            # Process POST request
            if 'clear' in request.params:
                removed_keys = g.op_trust_registry.remove_by_identity(my_identity)
                h.flash(_('Cleared %d policy objects') %(len(removed_keys)), 'notice')
            redirect(url('users-me'))

    @authenticated
    def clear_trust(self):
        realm = request.params.get('realm')
        realm = h.validate_realm_url(realm)
        if not realm:
            abort(400)
        c.my_identity = my_identity = get_identity()
        c.realm = realm
        if request.method == 'GET':
            c.action = url('users-clear-trust')
            c.csrf_token_field = h.secure_form.auth_token_hidden_field()
            return render('users/clear_trust.html')
        else:
            # Validate POST request
            self._validate_csrf_token()
            # Process POST request
            if 'clear' in request.params:
                g.op_trust_registry.remove(my_identity,realm)
                h.flash(_('Revoked trust to %s') % (realm), 'notice')
                log1.info('Revoked trust to %s for %s' %(realm, my_identity.uid))
            else:
                pass # nop
            redirect(url('users-me'))

    @authenticated
    def edit_trust(self):
        realm = request.params.get('realm')
        realm = h.validate_realm_url(realm)
        c.my_identity = my_identity = get_identity()
        c.realm = realm
        c.known_ax_attrs = g.op_ax_attr_types.items()
        c.known_sreg_attrs = g.op_sreg_attrs
        policy = g.op_trust_registry.get(my_identity, realm)
        if request.method == 'GET':
            c.page_title = _('Edit Trust') if realm else _('Add Trust')
            c.action = url('users-edit-trust')
            c.policy = copy.copy(policy) if policy else None
            c.csrf_token_field = h.secure_form.auth_token_hidden_field()
            return render('users/edit_trust.html')
        else:
            # Validate POST request
            self._validate_csrf_token()
            # Process POST request
            if 'save' in request.params:
                if not realm:
                    abort(400)
                policy = None
                ttl_seconds = None
                policy_allow = str(request.params.get('allow','always'))
                if policy_allow == 'always':
                    try:
                        ttl_seconds = int(request.params.get('ttl', 3600))
                    except:
                        ttl_seconds = 3600
                    exported_sreg_attrs = frozenset(filter(
                        lambda a: request.params.has_key('attr-sreg-%s' %(a)), g.op_sreg_attrs))
                    exported_ax_attrs = frozenset(filter(
                        lambda a: request.params.has_key('attr-ax-%s' %(a)), g.op_ax_attrs))
                    policy = trust_policy.Policy('always', exported_sreg_attrs, exported_ax_attrs);
                elif policy_allow == 'never':
                    policy = trust_policy.Policy('never', None, None);
                else:
                    # other policy-allow types (i.e except "always" and "never") are not meant 
                    # to be stored in the registry
                    pass
                if policy:
                    g.op_trust_registry.update(my_identity, realm, policy, ttl_seconds)
                    h.flash(_('Updated trust policy for %s') % (realm), 'notice')
                    log1.info('Saved trust policy to %s for %s' %(realm, my_identity.uid))
                else:
                    pass
            else:
                pass # nop
            redirect(url('users-me'))

    @authenticated
    def me(self):
        who_identity = get_who_identity()
        c.my_metadata = who_metadata = get_who_metadata()
        c.my_identity = my_identity = get_identity()
        c.my_userid = userid = who_identity['repoze.who.userid']
        c.my_common_name  = who_metadata.get('cn') or who_metadata.get('commonName')
        c.my_username = c.my_common_name or c.my_userid
        c.my_display_name = map(lambda s: s.decode('utf8'), c.my_metadata.get('displayName', []))
        c.add_trust_url = url('users-edit-trust')
        c.clear_trust_url = url('users-clear-all-trust')
        grants = []
        policies = g.op_trust_registry.get_by_identity(my_identity)
        for realm,policy in policies.items():
            edit_url   = url('users-edit-trust', realm=realm)
            clear_url = url('users-clear-trust', realm=realm)
            grants.append((realm, policy.allow, edit_url, clear_url))
        c.my_grants = grants
        c.logout_url = url('logout')
        return render('users/me.html')

    @authenticated
    def dump(self):
        c.who_identity = get_who_identity()
        c.logout_url = url('logout')
        return render('users/dump.html')

