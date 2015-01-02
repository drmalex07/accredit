"""Routes configuration

The more specific and detailed routes should be defined first so they
may take precedent over the more generic routes. For more information
refer to the routes manual at http://routes.groovie.org/docs/
"""
from routes import Mapper

def make_map(config):
    """Create, configure and return the routes Mapper"""
    mapper = Mapper(directory=config['pylons.paths']['controllers'],always_scan=config['debug'])
    mapper.minimization = False
    mapper.explicit = False

    # The ErrorController route (handles 404/500 error pages); it should
    # likely stay at the top, ensuring it can always be resolved

    mapper.connect('/error/{action}', controller='error')
    mapper.connect('/error/{action}/{id}', controller='error')

    # Custom routes

    m = mapper

    path_prefix = config.get('path_prefix', '').rstrip('/')
    if path_prefix:
        assert(path_prefix.startswith('/'))
        m = mapper.submapper(path_prefix=path_prefix)

    m.connect('home','/home', controller='home', action='index')
    m.connect('home-reg-dump','/home/reg-dump', controller='home', action='registry_dumps')

    m.connect('login-form','/login-form', controller='users', action='login_form')
    m.connect('login','/login', controller='users', action='login')
    m.connect('logout','/logout', controller='users', action='logout')
    m.connect('logged-in', '/logged-in', controller='users', action='logged_in')
    m.connect('logged-out', '/logged-out', controller='users', action='logged_out')
    m.connect('reset-password-form','/reset-password-form', controller='users', action='reset_password_form')
    m.connect('reset-password','/reset-password', controller='users', action='reset_password')
    m.connect('users-me','/users/me', controller='users', action='me')
    m.connect('users-clear-trust','/users/clear-trust', controller='users', action='clear_trust')
    m.connect('users-clear-all-trust','/users/clear-all-trust', controller='users', action='clear_all_trust')
    m.connect('users-edit-trust','/users/edit-trust', controller='users', action='edit_trust')

    m.connect('openid-yadis-with-uid', '/openid/yadis/{uid}', controller='openid_provider', action='show_yadis')
    m.connect('openid-yadis', '/openid/yadis', controller='openid_provider', action='show_yadis', uid='*')
    m.connect('openid-provider', '/openid/provide', controller='openid_provider', action='provide')
    m.connect('openid-identity', '/openid/identity/{uid}', controller='openid_provider', action='show_identity')
    m.connect('openid-identity-select', '/openid/identity-select', controller='openid_provider', action='show_identity', uid='*')
    m.connect('openid-ax-schema', '/openid/schema/ax/{typename}', controller='openid_provider', action='show_ax_schema')
    m.connect('openid-confirm', '/openid/confirm', controller='openid_provider', action='confirm')

    m.connect('/{controller}/{action}')
    m.connect('/{controller}/{action}/{id}')

    # Redirects

    mapper.redirect(path_prefix + '/', path_prefix + '/users/me')
    mapper.redirect(path_prefix, path_prefix + '/users/me')

    return mapper
