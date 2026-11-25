"""Read-only netlink watcher. Periodic recovery remains if the monitor exits."""
import subprocess
import threading

from .commands import ENVIRONMENT, IP


class NetworkEvents:
    def __init__(self, callback, popen=subprocess.Popen):
        self.callback, self.popen = callback, popen
        self.process = None
        self._closed = threading.Event()
        self.thread = None

    def start(self) -> None:
        try:
            self.process = self.popen([IP, 'monitor', 'link', 'address', 'route', 'rule'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=ENVIRONMENT)
        except OSError:
            return
        self.thread = threading.Thread(target=self._read, name='site-routing-netlink', daemon=True)
        self.thread.start()

    def _read(self) -> None:
        while not self._closed.is_set():
            if not self.process.stdout.readline(8192):
                return
            self.callback()

    def close(self) -> None:
        self._closed.set()
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            self.process.stdout.close()
        if self.thread:
            self.thread.join(timeout=3)
