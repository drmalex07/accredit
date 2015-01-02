import logging

from paste.deploy.converters import asbool

log1 = logging.getLogger(__name__)

class ServerNameFilter(object):
    ''' This middleware filters-out any requests not matching a specific server-name
    (as this is recognized by the "Host" HTTP request header)
    '''

    def __init__(self, app, server_name, header_key):
        ''' @param header_key is the appropriate key inside request.environ dict
        mapping to the requested "Host" value
        '''
        self.app = app
        self.server_name = str(server_name)
        self.header_key = str(header_key)
        return

    def __call__(self, environ, start_response):
        server_host = environ.get(self.header_key, '')
        if self.server_name == server_host:
            return self.app(environ, start_response)
        else:
            start_response("400 Bad request", [('content-type','text/plain')])
            return 'No service at %s' %(server_host)

def servername_filter_factory(global_conf, **app_conf):
    server_name = global_conf.get('server_name', 'localhost')
    header_key  = 'HTTP_HOST'
    if asbool(app_conf.get('request_is_forwarded', False)):
        header_key = 'HTTP_X_FORWARDED_HOST'
    log1.info ('Using %s as the "Host" request.environ key' %(header_key))
    def filter(app):
        return ServerNameFilter(app, server_name, header_key)
    return filter
