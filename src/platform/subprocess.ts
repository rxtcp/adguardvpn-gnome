import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import type {CommandResult} from '../domain/types.js';

export function runCli(cliPath: string, args: readonly string[], timeoutSeconds: number,
    cancellable: Gio.Cancellable): Promise<CommandResult> {
    return new Promise((resolve, reject) => {
        let process: Gio.Subprocess;
        try {
            process = Gio.Subprocess.new([cliPath, ...args],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE);
        } catch (error) {
            reject(error);
            return;
        }
        let timedOut = false;
        let timeoutId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, timeoutSeconds, () => {
            timeoutId = 0;
            timedOut = true;
            process.force_exit();
            return GLib.SOURCE_REMOVE;
        });
        const cancelId = cancellable.connect(() => process.force_exit());
        process.communicate_utf8_async(null, null, (source, result) => {
            if (timeoutId)
                GLib.Source.remove(timeoutId);
            cancellable.disconnect(cancelId);
            try {
                const [, stdout, stderr] = source!.communicate_utf8_finish(result);
                if (cancellable.is_cancelled())
                    reject(new Error('Cancelled'));
                else if (timedOut)
                    reject(new Error('Timeout'));
                else
                    resolve({success: source!.get_successful(), output: `${stdout ?? ''}\n${stderr ?? ''}`.trim()});
            } catch (error) {
                reject(error);
            }
        });
    });
}
