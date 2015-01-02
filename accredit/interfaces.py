import zope.interface

#
# Interfaces for various callbacks
#

class ILoginNameMapper(zope.interface.Interface):
    
    def to_name(login_name):
        ''' Map a @param login_name to a name used as the RDN naming attribute. '''
        pass

class IAxAttributeComposer(zope.interface.Interface):
    
    def compose_from(who_metadata, attr_alias, attr_type):
        ''' Calculates and returns an AX attribute value based on:
        @param metadata: (dict)
        @param attr_alias: attribute alias (as declared in the OP's config file)
        @param attr_type: atribute type URI
        '''
        pass

class IAccountManager(zope.interface.Interface):
    
    def get(uid):
        pass
    
    def set_enabled(uid, on=True):
        pass

    def set_password(uid, passwd):
        pass
    
    def set_email(uid, email):
        pass

