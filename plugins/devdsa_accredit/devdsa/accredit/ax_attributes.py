import zope.interface
import logging
import re
import copy
import ldap.dn
from paste.deploy.converters import asbool

from accredit.interfaces import IAxAttributeComposer

def convert_dn_to_path(dn):
    ''' Converts a DN to a path-like format '''
    if isinstance(dn,str):
        dn = ldap.dn.str2dn(dn)
    p = copy.copy(dn)
    p.reverse()
    path =  "//" + "/".join([ "+".join([r[1] for r in e]) for e in p ])
    return path

def convert_dn_to_relpath(base_path, dn):
    path = convert_dn_to_path(dn)
    if not path.startswith(base_path):
        return None
    path = path[len(base_path):]
    return path

class GroupOfNamesAttribute(object):

    zope.interface.implements(IAxAttributeComposer)

    def __init__(self, naming_context=None, metadata_key=None):
        assert (len(metadata_key))
        self.naming_context = naming_context
        self.base_dn = ldap.dn.str2dn(naming_context)
        self.base_path = convert_dn_to_path(self.base_dn)
        self.metadata_key = metadata_key
        return

    # implement IAxAttributeComposer

    def compose_from(self, metadata, alias, type_uri):
        assert (isinstance(metadata,dict))
        return [ convert_dn_to_relpath(self.base_path, p) for p in
            metadata.get(self.metadata_key, []) ]

class ClientObjectAttribute(object):

    zope.interface.implements(IAxAttributeComposer)

    def __init__(self):
        return

    # implement IAxAttributeComposer

    def compose_from(self, metadata, alias, type_uri):
        assert (isinstance(metadata,dict))

        result = {
            'clientId': int(metadata.get('clientIdentifier')[0]),
            'class': 'client',
            'commonName': metadata.get('cn')[0],
        }

        # Compute properties based on object's (auxiliary) classes

        object_classes = metadata.get('objectClass')

        if 'LawyerProperties' in object_classes:
            result['class'] = 'lawyer'
            result['lawyer'] = {
                'registrationCode': str(metadata.get('registrationCode')[0]),
                'isActive': asbool(metadata.get('isActive')[0]),
                'hasFinancialCapabilities': asbool(metadata.get('hasFinancialCapabilities')[0]),
            }
        elif 'PractitionerProperties' in object_classes:
            result['class'] = 'practitioner'
            result['practitioner'] = {
                'registrationCode': str(metadata.get('registrationCode')[0]),
                'isActive': asbool(metadata.get('isActive')[0]),
            }
        elif 'LawyerCompanyProperties' in object_classes:
            result['class'] = 'company'
            result['company'] = {
                'registrationCode': str(metadata.get('registrationCode')[0]),
                'isActive': asbool(metadata.get('isActive')[0]),
            }

        # Compute properties based on regular metadata (mirrored from LDAP attributes)

        if 'employeeID' in metadata:
            result['class'] = 'staff'
            result['staff'] = {
                'employeeId': int(metadata.get('employeeID')[0]),
                'employeeType': str(metadata.get('employeeType', ['staff'])[0]),
            }

        # Done

        return result


