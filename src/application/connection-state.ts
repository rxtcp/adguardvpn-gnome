export const CONNECTING_GRACE_SECONDS = 30;

export class ConnectionState {
    connected = false;
    currentLocation = '';
    busy = false;
    findingFastest = false;
    connectionRequestedAt = 0;
    statusUnavailableSince = 0;

    isStarting(now: number): boolean {
        return this.connectionRequestedAt > 0 &&
            now - this.connectionRequestedAt < CONNECTING_GRACE_SECONDS * 1_000_000;
    }
}
