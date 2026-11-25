"""Versioned root-only intent journal. A corrupt file never means no rules."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile
import threading
import uuid

from .domain import MAX_RULES, normalize_addresses, normalize_domain
from .models import Target, canonical_uuid
from .security import verified_open, verify_path

STATE_DIRECTORY = Path('/var/lib/adguardvpn-site-routing')
MAX_STATE_BYTES = 4 * 1024 * 1024


def new_state() -> dict:
    return {'schema_version': 1, 'installation_id': str(uuid.uuid4()), 'revision': 0,
            'rules': [], 'kernel': {'objects': [], 'known': [], 'tables': {}, 'priority': 0}, 'migrations': {}}


def validate_state(value: object) -> dict:
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        raise ValueError('Unsupported or corrupt Site Routing state; protections must be retained.')
    canonical_uuid(value.get('installation_id'))
    if type(value.get('revision')) is not int or value['revision'] < 0 or not isinstance(value.get('rules'), list) or len(value['rules']) > MAX_RULES:
        raise ValueError('Invalid Site Routing state.')
    identities = set()
    for rule in value['rules']:
        identity = canonical_uuid(rule['id'])
        if identity in identities or type(rule['owner_uid']) is not int or rule['owner_uid'] < 0:
            raise ValueError('Invalid rule ownership or identity.')
        identities.add(identity)
        if rule['domain'] != normalize_domain(rule['domain']) or rule.get('fallback') != 'block' or rule.get('enabled') is not True:
            raise ValueError('Invalid saved rule policy.')
        Target.parse(rule['target'])
        normalize_addresses(rule['addresses'])
    kernel = value.get('kernel')
    if not isinstance(kernel, dict) or not isinstance(kernel.get('objects'), list) or not isinstance(kernel.get('known'), list) or not isinstance(kernel.get('tables'), dict):
        raise ValueError('Missing kernel ownership journal.')
    if not isinstance(value.get('migrations'), dict):
        raise ValueError('Missing migration journal.')
    return value


class StateStore:
    def __init__(self, directory: Path = STATE_DIRECTORY, owner: int = 0):
        verify_path(directory, owner, private=True, directory=True)
        self.directory, self.owner = directory, owner
        self.path = directory / 'state.json'
        self._mutex = threading.RLock()
        self._depth = 0
        self._empty = new_state()

    @contextmanager
    def lock(self):
        with self._mutex:
            if self._depth:
                yield
                return
            descriptor = verified_open(self.directory / 'state.lock', os.O_CREAT | os.O_RDWR, self.owner)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                self._depth = 1
                yield
            finally:
                self._depth = 0
                os.close(descriptor)

    def load(self) -> dict:
        try:
            descriptor = verified_open(self.path, os.O_RDONLY, self.owner)
        except FileNotFoundError:
            return json.loads(json.dumps(self._empty))
        except OSError as error:
            raise RuntimeError('Cannot trust Site Routing state.') from error
        with os.fdopen(descriptor, 'r', encoding='utf-8') as handle:
            contents = handle.read(MAX_STATE_BYTES + 1)
        if len(contents.encode('utf-8')) > MAX_STATE_BYTES:
            raise ValueError('Site Routing state exceeds the size limit.')
        try:
            return validate_state(json.loads(contents))
        except (KeyError, TypeError) as error:
            raise ValueError('Corrupt Site Routing state.') from error

    def save(self, state: dict) -> None:
        validate_state(state)
        contents = json.dumps(state, sort_keys=True, ensure_ascii=True)
        if len(contents) > MAX_STATE_BYTES:
            raise ValueError('Site Routing state exceeds the size limit.')
        if self.path.exists():
            previous = json.dumps(self.load(), sort_keys=True)
            self._replace(self.directory / 'state.previous.json', previous)
        self._replace(self.path, contents)

    def _replace(self, path: Path, contents: str) -> None:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.directory,
                                             prefix='.write-', delete=False) as handle:
                temporary = handle.name
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
