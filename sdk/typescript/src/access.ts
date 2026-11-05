/** Header carrying the server-wide access password on every /relay/v1 request. */
export const ACCESS_HEADER = 'Relay-Access';

/** Validates an optional access password: 8–128 printable ASCII characters (0x21–0x7E), no spaces. */
export function checkAccessPassword(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || !/^[\x21-\x7e]{8,128}$/.test(value)) throw new Error('Invalid relay access password');
  return value;
}

/** Headers to merge into a request; empty when no password is configured. */
export function accessHeaders(value: string | undefined): Record<string, string> {
  return value === undefined ? {} : { [ACCESS_HEADER]: value };
}
