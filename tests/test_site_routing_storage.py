import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from site_routing.storage import StateStore, new_state


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
