import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import {errorMessage} from '../domain/cli-output.js';

export type TerminalAction = 'connect' | 'switch' | 'fastest' | 'switch-fastest' | 'disconnect';

export function openActionTerminal(cliPath: string, action: TerminalAction, location = ''): boolean {
    const terminal = ['ptyxis', 'kgx', 'gnome-terminal', 'konsole', 'xterm']
        .map(name => GLib.find_program_in_path(name)).find(path => path !== null);
    if (!terminal)
        return false;
    // User-provided values are positional arguments, never shell source.
    const script = [
        'case "$2" in',
        '  connect) "$1" connect -l "$3" ;;',
        '  switch) "$1" disconnect && "$1" connect -l "$3" ;;',
        '  fastest) "$1" connect -f ;;',
        '  switch-fastest) "$1" disconnect && "$1" connect -f ;;',
        '  disconnect) "$1" disconnect ;;',
        '  *) exit 2 ;;',
        'esac',
        'result=$?',
        'if [ "$result" -ne 0 ]; then',
        '  printf "\\nAdGuard VPN error. Press Enter to close this window..."',
        '  read -r _',
        'fi',
    ].join('\n');
    const prefix = terminal.endsWith('/xterm') ? ['-e'] : ['--'];
    try {
        Gio.Subprocess.new([terminal, ...prefix, 'bash', '-c', script, 'adguardvpn', cliPath, action, location],
            Gio.SubprocessFlags.NONE);
        return true;
    } catch (error) {
        console.error(`AdGuard VPN: cannot open terminal: ${errorMessage(error)}`);
        return false;
    }
}
