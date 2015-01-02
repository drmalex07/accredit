"""Pylons environment configuration"""
import os
import logging

from genshi.template import TemplateLoader
from genshi.filters.i18n import Translator

import pylons
from pylons.configuration import PylonsConfig

from paste.deploy.converters import aslist, asbool

from sqlalchemy import engine_from_config

import accredit.lib.app_globals as app_globals
import accredit.lib.helpers
from accredit.config.routing import make_map
from accredit.model import init_model

log1 = logging.getLogger(__name__)

def load_environment(global_conf, app_conf):
    """Configure the Pylons environment via the ``pylons.config`` object
    """
    config = PylonsConfig()

    # Pylons paths

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    static_paths = []
    template_paths = []

    theme = app_conf.get('theme')
    if theme:
        template_paths.append(os.path.join(root, 'themes', theme, 'templates'))
        static_paths.append(os.path.join(root, 'themes', theme, 'public'))

    template_paths.extend([os.path.join(root, 'templates')])
    static_paths.extend([os.path.join(root, 'public')])

    paths = dict(
        root = root,
        controllers = os.path.join(root, 'controllers'),
        static_files = static_paths,
        templates = template_paths
    )

    # Initialize config with the basic options
    config.init_app(global_conf, app_conf, package='accredit', paths=paths)

    config['routes.map'] = make_map(config)
    config['pylons.app_globals'] = app_globals.Globals(config)
    config['pylons.h'] = accredit.lib.helpers

    # Setup cache object as early as possible
    import pylons
    pylons.cache._push_object(config['pylons.app_globals'].cache)

    # Translator (i18n)
    translator = Translator(pylons.translator)

    def template_loaded(template):
        translator.setup(template)

    # Create the Genshi TemplateLoader
    config['pylons.app_globals'].genshi_loader = TemplateLoader(
        paths['templates'], auto_reload=True, callback=template_loaded)

    # Setup the SQLAlchemy database engine
    engine = engine_from_config(config, 'sqlalchemy.')
    init_model(engine)

    # CONFIGURATION OPTIONS HERE (note: all config options will override
    # any Pylons config options)

    return config
