import Gio from 'gi://Gio';
import {isValidLocation} from '../domain/preferences.js';
import type {CommandResult} from '../domain/types.js';
import {getCliPath, getProtectedControlPath} from '../platform/paths.js';
import {runCli} from '../platform/subprocess.js';

export class VpnClient {
    readonly cliPath = getCliPath();
    readonly controlPath = getProtectedControlPath();
    private readonly cancellable = new Gio.Cancellable();

    get available(): boolean { return Boolean(this.cliPath || this.controlPath); }
    get cancelled(): boolean { return this.cancellable.is_cancelled(); }
    cancel(): void { this.cancellable.cancel(); }

    listLocations(timeoutSeconds: number): Promise<CommandResult> {
        return runCli(this.cliPath!, ['list-locations'], timeoutSeconds, this.cancellable);
    }

    runAction(args: readonly string[], timeoutSeconds: number): Promise<CommandResult> {
        if (!this.controlPath)
            return runCli(this.cliPath!, args, timeoutSeconds, this.cancellable);
        if (args[0] === 'connect' && args[1] === '-f')
            return runCli(this.controlPath, ['connect', '--fastest'], timeoutSeconds, this.cancellable);
        if (args[0] === 'connect' && args[1] === '-l' && isValidLocation(args[2]))
            return runCli(this.controlPath, ['connect', '--location', args[2]], timeoutSeconds, this.cancellable);
        if (args.length === 1 && ['disconnect', 'status'].includes(args[0]!))
            return runCli(this.controlPath, args, timeoutSeconds, this.cancellable);
        return Promise.reject(new Error('Unsupported protected helper operation'));
    }
}
