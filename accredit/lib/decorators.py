import pickle
import binascii

from binascii import hexlify

from pylons import request, tmpl_context as c

class ContextSensitiveMemoizer(object):
    ''' Memoize a result into request's context (c) '''
    def __init__(self,fn):
        self.fn = fn

    def __call__(self, *args):

        if not hasattr(c,'memoized'):
            c.memoized = {}

        if len(args):
            k = "%s-%s" %(self.fn.__name__, hexlify(pickle.dumps(args)))
        else:
            k = "%s" %(self.fn.__name__)

        v = None
        try:
            v = c.memoized[k]
        except KeyError:
            v = c.memoized[k] = self.fn(*args)

        return v

def context_sensitive_memoizer(fn):
    return ContextSensitiveMemoizer(fn)


