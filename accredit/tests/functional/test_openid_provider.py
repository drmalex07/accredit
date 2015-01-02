from accredit.tests import *

class TestOpenidProviderController(TestController):

    def test_index(self):
        response = self.app.get(url(controller='openid_provider', action='index'))
        # Test response...
