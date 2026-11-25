"""Bounded JSON envelope shared by the asynchronous D-Bus frontend and service."""
import json

from .domain import MAX_REQUEST_BYTES
from .protocol import validate_request

BUS_NAME = 'org.gnome.AdGuardVPN.SiteRouting'
OBJECT_PATH = '/org/gnome/AdGuardVPN/SiteRouting'
INTERFACE = BUS_NAME
INTROSPECTION = f'''<node><interface name="{INTERFACE}">
<method name="Request"><arg type="s" direction="in" name="request_json"/>
<arg type="s" direction="out" name="response_json"/></method>
</interface></node>'''


def envelope(data=None, code=None, message=None) -> str:
    result = {'schema_version': 1, 'ok': code is None}
    result['data' if code is None else 'error'] = data if code is None else {'code': code, 'message': message}
    return json.dumps(result, ensure_ascii=True)


class RequestDispatcher:
    def __init__(self, manager, authorizer):
        self.manager, self.authorizer = manager, authorizer

    def dispatch(self, sender: str, contents: str) -> str:
        try:
            if not isinstance(contents, str) or len(contents.encode('utf-8')) > MAX_REQUEST_BYTES:
                raise ValueError('Site Routing request exceeds the input limit.')
            request = validate_request(json.loads(contents))
        except (ValueError, TypeError):
            return envelope(code='invalid-request', message='Invalid Site Routing request.')
        try:
            uid, username = self.authorizer.identity(sender, request['operation'])
            return envelope(self.manager.handle(request, uid, username))
        except PermissionError:
            return envelope(code='not-authorized', message='Authorization was not granted for this operation or rule.')
        except ValueError as error:
            return envelope(code='invalid-operation', message=str(error))
        except (OSError, RuntimeError):
            return envelope(code='apply-error', message='The operation did not complete. Review rule status; protection is not confirmed by this response.')
        except Exception:
            self.manager.emergency_block()
            return envelope(code='internal-error', message='Site Routing failed unexpectedly; review the retained protection state.')
