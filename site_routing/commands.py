"""Bounded calls to fixed system programs; no shell, paths or arguments from IPC."""
import json
import subprocess

from .route_netlink import restore_legacy_route

IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}


def failure_reason(stderr: str) -> str:
    text = stderr.lower()
    if text.startswith('device ') and 'does not exist' in text:
        return 'kernel interface disappeared'
    for phrase, reason in (
        ('no such device', 'kernel interface disappeared'),
        ('cannot find device', 'kernel interface disappeared'),
        ('network is unreachable', 'kernel reports the network is unreachable'),
        ('operation not permitted', 'permission was denied'),
        ('permission denied', 'permission was denied'),
        ('file exists', 'an existing object prevents installation'),
        ('invalid argument', 'kernel rejected the operation parameters'),
    ):
        if phrase in text:
            return reason
    return 'network command failed'


class CommandRunner:
    restore_legacy_route = staticmethod(restore_legacy_route)

    def run(self, argv: list[str], input_text: str | None = None) -> str:
        try:
            result = subprocess.run(argv, input=input_text, stdin=None if input_text is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    env=ENVIRONMENT, timeout=12, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError('A required network command is unavailable or timed out.') from error
        if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
            reason = failure_reason(getattr(result, 'stderr', ''))
            raise RuntimeError(f'{reason}; no successful routing state was confirmed.')
        return result.stdout

    def read_ip(self, family: int, *args: str) -> list:
        value = json.loads(self.run([IP, '-N', f'-{family}', '-j', *args]))
        if not isinstance(value, list):
            raise ValueError('Invalid iproute2 response.')
        protocols = {'0': 'unspec', '2': 'kernel', '3': 'boot', '4': 'static'}
        scopes = {'0': 'global', '200': 'site', '253': 'link', '254': 'host', '255': 'nowhere'}
        types = {'1': 'lookup' if args[:1] == ('rule',) else 'unicast', '6': 'blackhole',
                 '7': 'unreachable', '8': 'prohibit'}
        for row in value:
            if not isinstance(row, dict):
                raise ValueError('Invalid iproute2 object.')
            if 'table' in row:
                table = row['table']
                if type(table) not in (str, int) or not str(table).isdecimal() or not 0 <= int(table) <= 4294967295:
                    raise ValueError('Invalid numeric routing table.')
                row['table'] = int(table)
            for field, names in (('protocol', protocols), ('scope', scopes), ('type', types), ('action', types)):
                if field in row:
                    row[field] = names.get(str(row[field]), row[field])
        return value

    def write_ip(self, family: int, *args: str) -> None:
        self.run([IP, f'-{family}', *args])

    def read_links(self) -> list:
        value = json.loads(self.run([IP, '-j', '-d', 'address', 'show']))
        if not isinstance(value, list):
            raise ValueError('Invalid kernel interface response.')
        return value

    def nft_json(self, *args: str) -> dict:
        value = json.loads(self.run([NFT, '-j', *args]))
        if not isinstance(value, dict) or not isinstance(value.get('nftables'), list):
            raise ValueError('Invalid nftables response.')
        return value

    def nft_apply(self, script: str) -> None:
        self.run([NFT, '-f', '-'], script)
