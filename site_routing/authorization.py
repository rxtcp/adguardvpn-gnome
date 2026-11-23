"""Polkit identity is the actual system-bus caller, never a supplied UID/PID."""
import pwd
import re

from .protocol import READ_OPERATIONS, WRITE_OPERATIONS

POLKIT = 'org.freedesktop.PolicyKit1'
AUTHORITY = '/org/freedesktop/PolicyKit1/Authority'
ACTION = 'org.gnome.adguardvpn.site-routing'


class PolkitAuthorizer:
    def __init__(self, bus, account=pwd.getpwuid):
        self.bus, self.account = bus, account

    def identity(self, sender: str, operation: str) -> tuple[int, str]:
        if not re.fullmatch(r':\d+\.\d+', sender) or operation not in READ_OPERATIONS | WRITE_OPERATIONS:
            raise PermissionError('An authenticated system-bus caller is required.')
        uid = self.bus.call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus',
                            'GetConnectionUnixUser', '(s)', (sender,))[0]
        modifying = operation in WRITE_OPERATIONS
        subject = ('system-bus-name', {'name': self.bus.glib.Variant('s', sender)})
        result = self.bus.call(POLKIT, AUTHORITY, POLKIT + '.Authority', 'CheckAuthorization',
            '((sa{sv})sa{ss}us)', (subject, ACTION + ('.modify' if modifying else '.read'), {},
                                  1 if modifying else 0, ''), timeout=120000 if modifying else 5000)[0]
        if result[0] is not True or type(uid) is not int or not 0 <= uid <= 4294967295:
            raise PermissionError('Authorization was not granted.')
        try:
            return uid, self.account(uid).pw_name
        except KeyError as error:
            raise PermissionError('The calling local account is no longer available.') from error
