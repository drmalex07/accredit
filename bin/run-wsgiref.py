#!/usr/bin/env python

import logging, logging.config
import os.path

from paste.deploy import loadapp
from wsgiref.simple_server import make_server

here = os.path.dirname(os.path.realpath(__file__))

ini_file = os.path.join(here, 'test-1.ini')

logging.config.fileConfig(ini_file)

app = loadapp('config:%s' %(ini_file));

httpd = make_server('', 5003, app)
print "Serving on port 5003 ..."
httpd.serve_forever()

