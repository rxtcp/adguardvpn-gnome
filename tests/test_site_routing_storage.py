import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from site_routing.storage import StateStore, new_state, validate_state
from site_routing.security import verify_path
from site_routing.rule_operations import change_rule
from site_routing_fakes import Registry, TARGET


class RoutingStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / '.tmp')
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.store = StateStore(self.path, owner=os.getuid())

    def test_atomic_private_state_and_verified_backup(self):
        state = self.store.load()
        self.assertEqual(state['schema_version'], 1)
        with self.store.lock():
            self.store.save(state)
            state['revision'] += 1
            self.store.save(state)
        self.assertEqual(self.store.load()['revision'], 1)
        self.assertEqual(json.loads((self.path / 'state.previous.json').read_text())['revision'], 0)
        self.assertEqual((self.path / 'state.json').stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.path.glob('.write-*')))

    def test_failed_replace_keeps_existing_intent_and_cleans_staging(self):
        state = self.store.load()
        self.store.save(state)
        with patch('site_routing.storage.os.replace', side_effect=OSError('disk error')):
            with self.assertRaises(OSError):
                self.store.save({**state, 'revision': 1})
        self.assertEqual(self.store.load()['revision'], 0)
        self.assertFalse(list(self.path.glob('.write-*')))

    def test_bad_version_corruption_and_unsafe_file_permissions_are_not_empty_configuration(self):
        for content in ('{bad', '{"schema_version":2}', '[]'):
            (self.path / 'state.json').write_text(content)
            (self.path / 'state.json').chmod(0o600)
            with self.assertRaises((ValueError, RuntimeError)):
                self.store.load()
        (self.path / 'state.json').write_text(json.dumps(new_state()))
        (self.path / 'state.json').chmod(0o666)
        with self.assertRaises(RuntimeError):
            self.store.load()

    def test_symlink_files_and_writable_state_directory_are_rejected(self):
        outside = self.path / 'outside'
        outside.write_text(json.dumps(new_state()))
        (self.path / 'state.json').symlink_to(outside)
        with self.assertRaises(RuntimeError):
            self.store.load()
        self.path.chmod(0o777)
        with self.assertRaises(RuntimeError):
            StateStore(self.path, owner=os.getuid())
        self.path.chmod(0o700)

    def test_nested_lock_is_reentrant_and_owner_not_client_controlled(self):
        with self.store.lock():
            with self.store.lock():
                self.store.save(self.store.load())
        with self.assertRaises(RuntimeError):
            StateStore(self.path, owner=os.getuid() + 1)

    def test_saved_rule_schema_identity_and_kernel_manifest_are_validated_before_use(self):
        state = new_state()
        change_rule(state, {'operation': 'add-rule', 'domain': 'one.example', 'target': TARGET},
                    Registry().discover(), os.getuid(), 'fixtureuser', 1000)
        self.assertEqual(validate_state(state), state)
        self.store.save(state)
        self.assertEqual(self.store.load()['rules'][0]['domain'], 'one.example')
        invalid = [{**state, 'revision': -1}, {**state, 'revision': True}, {**state, 'rules': {}},
                   {**state, 'rules': state['rules'] * 129}, {**state, 'rules': state['rules'] * 2},
                   {**state, 'kernel': {}}, {**state, 'migrations': []}]
        for changed in ({'owner_uid': -1}, {'owner_uid': True}, {'domain': 'ONE.example'},
                        {'fallback': 'default'}, {'enabled': False}, {'addresses': ['127.0.0.1']}):
            invalid.append({**state, 'rules': [{**state['rules'][0], **changed}]})
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError): validate_state(value)
        self.store.path.write_text(json.dumps({**state, 'rules': [{}]}))
        with self.assertRaisesRegex(ValueError, 'Corrupt'): self.store.load()

    def test_size_limits_and_staging_creation_failure_preserve_prior_state(self):
        self.store.save(new_state())
        original = self.store.path.read_text()
        with patch('site_routing.storage.MAX_STATE_BYTES', 10):
            with self.assertRaisesRegex(ValueError, 'size limit'): self.store.load()
            with self.assertRaisesRegex(ValueError, 'size limit'): self.store.save(new_state())
        with patch('site_routing.storage.tempfile.NamedTemporaryFile', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.store.save(new_state())
        self.assertEqual(self.store.path.read_text(), original)

    def test_directory_type_and_private_permissions_are_enforced_separately_from_writability(self):
        self.path.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, 'private'): StateStore(self.path, owner=os.getuid())
        self.path.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError, 'type or owner'): verify_path(self.path, os.getuid())
        regular = self.path / 'regular'
        regular.write_text('fixture'); regular.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'type or owner'): verify_path(regular, os.getuid(), directory=True)
