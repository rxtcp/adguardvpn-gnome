export function cleanCliOutput(output: string): string {
    return output
        .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g, '')
        .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
        .replace(/\r/g, '');
}

export function errorMessage(error: unknown): string {
    return typeof error === 'object' && error !== null && 'message' in error
        ? String(error.message) : String(error);
}
