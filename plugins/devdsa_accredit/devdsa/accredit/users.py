import zope.interface
import logging
import re

from accredit.interfaces import ILoginNameMapper

class LoginNameMapper(object):

    zope.interface.implements(ILoginNameMapper)

    re_lawyer_code = re.compile('^([0-7][0-9])([0-9]{6,6})$')

    def __init__(self, rdn_lawyer_prefix='L'):
        self.rdn_lawyer_prefix = rdn_lawyer_prefix

    def to_name(self, login_name):
        ''' Map the login_name, entered by the user, to a name value corresponding
        to the RDN of a candidate directory entry.
        '''
        cls = self.__class__
        name = login_name
        if cls.re_lawyer_code.match(name):
            name = self.rdn_lawyer_prefix + name
        return name

