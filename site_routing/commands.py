"""Bounded calls to fixed system programs; no shell, paths or arguments from IPC."""
import json
import subprocess

IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}


class CommandRunner:
    def run(self, argv: list[str], input_text: str | None = None) -> str:
        try:
            result = subprocess.run(argv, input=input_text, stdin=None if input_text is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    env=ENVIRONMENT, timeout=12, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError('A required network command is unavailable or timed out.') from error
        if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
            raise RuntimeError('A network command failed; no successful routing state was confirmed.')
        return result.stdout

    def read_ip(self, family: int, *args: str) -> list:
        value = json.loads(self.run([IP, f'-{family}', '-j', *args]))
        if not isinstance(value, list):
            raise ValueError('Invalid iproute2 response.')
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
