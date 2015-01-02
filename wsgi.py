import sys
import os.path

here = os.path.dirname(os.path.realpath(__file__))
ini_file = os.path.join(here, 'production.ini')

# Activate enviroment
activate_this = os.path.realpath(os.path.join(here, '../..', 'pyenv/bin/activate_this.py'))
execfile(activate_this, dict(__file__=activate_this))

# Setup loggers
import logging, logging.config
logging.config.fileConfig(ini_file)

logging.info('Using executable=%s' %(sys.executable))
logging.info('Using path=%s' %(sys.path))
logging.info('Loading app from config file: %s ...' %(ini_file))

# Load WSGI application
from paste.deploy import loadapp
application = loadapp('config:%s' %(ini_file));

