"""Helper functions

Consists of functions to typically be used within templates, but also
available to Controllers. This module is available to templates as 'h'.
"""

import re
import json
import urlparse

import webhelpers.pylonslib.secure_form as secure_form
import webhelpers.pylonslib.flash

from genshi.core import Markup

from paste.deploy.converters import aslist, asbool, asint

from pylons import url as url_for
from pylons import config
from pylons import app_globals as g

flash = webhelpers.pylonslib.flash.Flash()

def site_name():
    return g.site_name

def site_lang():
    return g.site_lang

def describe_ax_attr(alias):
    return g.op_ax_attr_descriptions.get(alias)

def validate_url(s, allowed_protocols=None):
    p = urlparse.urlparse(str(s))
    if not p:
        return None
    if allowed_protocols and not (p.scheme in allowed_protocols):
        return None
    return p.geturl()

def validate_realm_url(s):
    p = urlparse.urlparse(str(s))
    if not p:
        return None
    if not (p.scheme in ['http','https']):
        return None
    if (p.query) or (p.fragment):
        return None
    return p.geturl()

