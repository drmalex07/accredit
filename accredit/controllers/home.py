import logging

from pylons import request, response, session, tmpl_context as c, url
from pylons.controllers.util import abort, redirect
from pylons.i18n import (get_lang, set_lang, _)
from pylons import app_globals as g
from pylons import config

from accredit.lib.base import BaseController, render
from accredit.lib.auth.helpers import (is_authenticated, get_identity, get_who_identity, get_who_metadata)

import accredit.lib.helpers as h

log = logging.getLogger(__name__)

class HomeController(BaseController):

    def index(self):
        return render('home/index.html')

    def brk(self):
        raise Exception ('B')
        return ''

    def registry_dumps(self):
        if (h.asbool(config['global_conf']['debug'])):
            c.dump = g.op_trust_registry.dumps()
            return render('home/registry_dumps.html')
        else:
            abort(403)
