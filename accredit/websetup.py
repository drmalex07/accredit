"""Setup the accredit application"""
import logging

import pylons.test

from accredit.config.environment import load_environment
from accredit.model.meta import Session, Base

log = logging.getLogger(__name__)

def setup_app(command, conf, vars):
    # Don't reload the app if it was loaded under the testing environment
    if not pylons.test.pylonsapp:
        load_environment(conf.global_conf, conf.local_conf)
    # Create the tables if they don't already exist
    log.info("Creating tables")
    Base.metadata.drop_all(checkfirst=True, bind=Session.bind)
    Base.metadata.create_all(bind=Session.bind)
    log.info("Successfull setup")
