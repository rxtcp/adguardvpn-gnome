"""Deterministic Site Routing fixtures; all values are synthetic."""
from contextlib import contextmanager
import copy

from site_routing.models import NetworkPath, Provider, Target
from site_routing.storage import new_state

NM_ID = '00000000-0000-4000-8000-000000000001'
RULE_ID = '00000000-0000-4000-8000-000000000002'
TARGET = {'kind': 'networkmanager', 'id': NM_ID}
PATH4 = NetworkPath('fixturevpn', 17, '192.0.2.2')
PATH6 = NetworkPath('fixturevpn', 17, '2001:db8:1::2')


class MemoryStore:
    def __init__(self):
        self.state = new_state()
        self.writes = []

    @contextmanager
    def lock(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def save(self, state):
        self.state = copy.deepcopy(state)
        self.writes.append(self.load())


class Registry:
    def __init__(self):
        self.providers = [Provider(Target.parse(TARGET), 'Fixture VPN', {4: PATH4, 6: PATH6}),
                          Provider(Target('direct', 'direct'), 'Direct', {4: NetworkPath('fixturewan', 4, '192.0.2.3', '192.0.2.1')})]
        self.calls = 0

    def discover(self):
        self.calls += 1
        return {provider.target.key: provider for provider in self.providers}


class Resolver:
    def __init__(self):
        self.answers = {'one.example': (('198.51.100.8', '2001:db8::8'), 60),
                        'two.example': (('198.51.100.8',), 60)}
        self.calls = []

    def resolve(self, domain, provider):
        self.calls.append((domain, provider))
        answer = self.answers[domain]
        if isinstance(answer, Exception):
            raise answer
        return answer


class Kernel:
    def __init__(self, store):
        self.store = store
        self.calls = []
        self.error = None

    def apply(self, assignments, journal, installation_id, approved=(), checkpoint=None):
        self.calls.append(('apply', copy.deepcopy(assignments)))
        assert set(assignments) <= set(self.store.state['kernel']['known'])
        if self.error:
            raise self.error
        return {**journal, 'known': sorted(assignments)}

    def block(self, addresses, installation_id):
        self.calls.append(('block', set(addresses)))

    def diagnostics(self, addresses):
        return [{'address': address} for address in addresses]
