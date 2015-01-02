import zope.interface

from accredit.interfaces import IAccountManager

class AccountManager(object):
    zope.interface.implements(IAccountManager)
    
    def __init__(self):
        pass
    
    # IAccountManager interface
    
    '''
    def get(self, uid):
        pass
    
    def set_enabled(self, uid, on=True):
        pass

    def set_password(self, uid, passwd):
        pass
    
    def set_email(self, uid, email):
        pass
    '''

