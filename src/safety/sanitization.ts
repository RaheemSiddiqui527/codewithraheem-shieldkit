/**
 * Sanitizes untrusted strings (such as file paths, code evidence, or user messages)
 * to prevent terminal escape sequence injection (CSI, OSC, APC sequences) and control characters.
 */

// Matches ANSI escape codes, terminal cursor controls, and color sequences
const ANSI_REGEX =
  /[\u001B\u009B][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d\/#&.:=?%@~_]*)*)?\u0007)|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-ntqry=><~]))/g;

// Matches non-printable control characters except standard whitespace (\t, \n, \r)
const CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g;

export function stripAnsi(str: string): string {
  if (typeof str !== 'string') return '';
  return str.replace(ANSI_REGEX, '');
}

export function sanitizeTerminalString(str: string): string {
  if (typeof str !== 'string') return '';
  // First strip ANSI escape sequences, then remove other non-printable control characters
  return stripAnsi(str).replace(CONTROL_CHARS_REGEX, '');
}

/**
 * Truncates evidence cleanly with an indicator if it exceeds maximum preview length.
 */
export function truncateEvidence(str: string, maxLength: number = 200): string {
  const sanitized = sanitizeTerminalString(str).trim();
  if (sanitized.length <= maxLength) {
    return sanitized;
  }
  return sanitized.slice(0, maxLength - 3) + '...';
}
