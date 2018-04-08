from puresasl import QOP
from puresasl.client import SASLClient
from puresasl.mechanisms import mechanisms


class MockSASLClient(SASLClient):
    def __init__(self, *args, **kwds):
        SASLClient.__init__(self, 'testhost')

    def choose_mechanism(self, mechanism_choices, *args, **kwds):
        mech_class = mechanisms[mechanism_choices[0]]
        self.mechanism = mech_class.name
        self._chosen_mech = mech_class(self, **self._mech_props)

    def process(self, challenge=None):
        return challenge

    @property
    def qop(self):
        return QOP.AUTH
