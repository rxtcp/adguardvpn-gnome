import importlib.util
import io
import os
from pathlib import Path
from contextlib import redirect_stderr
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


class RoutingInstallationTests(unittest.TestCase):
    def test_polkit_changes_require_interactive_admin_authentication_not_passwordless_vpn_action(self):
        policy = ET.parse(ROOT / 'routing_system/org.gnome.adguardvpn.site-routing.policy')
        actions = {element.attrib['id']: element for element in policy.findall('action')}
        self.assertEqual(actions['org.gnome.adguardvpn.site-routing.modify'].findtext('defaults/allow_active'), 'auth_admin')
        self.assertEqual(actions['org.gnome.adguardvpn.site-routing.read'].findtext('defaults/allow_active'), 'yes')
        self.assertTrue(all(element.findtext('defaults/allow_any') == 'no' for element in actions.values()))
        self.assertTrue(all(element.findtext('defaults/allow_inactive') == 'no' for element in actions.values()))

    def test_early_guard_orders_networkmanager_after_persisted_address_protection(self):
        early = (ROOT / 'routing_system/adguardvpn-site-routing-guard.service').read_text()
        dependency = (ROOT / 'routing_system/10-adguardvpn-site-routing.conf').read_text()
        manager = (ROOT / 'routing_system/adguardvpn-site-routing.service').read_text()
        self.assertIn('Before=network-pre.target NetworkManager.service', early)
        self.assertIn('DefaultDependencies=no', early)
        self.assertIn('Requires=adguardvpn-site-routing-guard.service', dependency)
        self.assertIn('After=adguardvpn-site-routing-guard.service', dependency)
        self.assertIn('Restart=on-failure', manager)
        self.assertIn('StateDirectoryMode=0700', manager)
        self.assertIn(' -I -B ', early)

    def test_system_bus_name_is_root_owned_and_source_bootstrap_refuses_nonroot_execution(self):
        tree = ET.parse(ROOT / 'routing_system/org.gnome.AdGuardVPN.SiteRouting.conf')
        policy = tree.find("policy[@user='root']")
        self.assertIsNotNone(policy.find("allow[@own='org.gnome.AdGuardVPN.SiteRouting']"))
        source = ROOT / 'routing_system/launch.py'
        spec = importlib.util.spec_from_file_location('routing_bootstrap', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module.os, 'geteuid', return_value=1000), redirect_stderr(io.StringIO()):
            self.assertEqual(module.main(['serve']), 1)
