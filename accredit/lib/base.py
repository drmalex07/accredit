"""The base Controller API

Provides the BaseController class for subclassing.
"""

from pylons.controllers import WSGIController
from pylons.templating import render_genshi as render

from pylons import app_globals as g
from pylons.i18n import (get_lang, set_lang, _)

from accredit.model.meta import Session

class BaseController(WSGIController):

    def __call__(self, environ, start_response):
        """Invoke the Controller"""

        # Prepare the environment for all controllers

        set_lang(g.site_lang)

        # WSGIController.__call__ dispatches to the Controller method
        # the request is routed to. This routing information is
        # available in environ['pylons.routes_dict']
        try:
            return WSGIController.__call__(self, environ, start_response)
        finally:
            Session.remove()
