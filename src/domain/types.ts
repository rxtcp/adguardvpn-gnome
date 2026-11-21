export interface ServerLocation {
    iso: string;
    country: string;
    city: string;
    ping: number | null;
}

export interface PreferredLocation {
    location: string;
    iso: string | null;
}

export interface CountryGroup {
    country: string;
    cities: ServerLocation[];
}

export type LocationGroups = Map<string, CountryGroup>;
export type VpnStatus =
    | {connected: false; subtitle: string}
    | {connected: true; subtitle: string; location: string | null};

export interface CommandResult {
    success: boolean;
    output: string;
}

export interface ToggleView {
    subtitle: string | null;
    checked: boolean;
    reactive: boolean;
}

export type ConnectionRequest =
    | {kind: 'fastest'}
    | {kind: 'location'; location: string; iso?: string | null};
