import { sanitizeTerminalString } from './sanitization.js';

export interface SecretPattern {
  name: string;
  regex: RegExp;
  mask: (...args: string[]) => string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  // AWS Access Key ID (e.g. AKIAIOSFODNN7EXAMPLE)
  {
    name: 'AWS Access Key ID',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    mask: (match) => `${match.slice(0, 4)}***[REDACTED_AWS_KEY]***`,
  },
  // AWS Secret Access Key (e.g. 40-char base64-like string)
  {
    name: 'AWS Secret Access Key',
    regex: /(aws_secret_access_key\s*[:=]\s*["']?)([A-Za-z0-9/+=]{40})(["']?)/gi,
    mask: (_match, prefix, _secret, suffix) => `${prefix}***[REDACTED_AWS_SECRET]***${suffix}`,
  },
  // GitHub Personal Access Token (classic & fine-grained)
  {
    name: 'GitHub Token',
    regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/g,
    mask: (match) => `${match.slice(0, 4)}***[REDACTED_GITHUB_TOKEN]***`,
  },
  // Anthropic API Key (must precede generic sk- pattern)
  {
    name: 'Anthropic API Key',
    regex: /\b(sk-ant-[A-Za-z0-9_-]{32,100})\b/g,
    mask: (match) => `${match.slice(0, 7)}***[REDACTED_ANTHROPIC_KEY]***`,
  },
  // OpenAI API Key
  {
    name: 'OpenAI API Key',
    regex: /\b(sk-(?!ant-)(?:live|proj)?[A-Za-z0-9_-]{32,64})\b/g,
    mask: (match) => `${match.slice(0, 3)}***[REDACTED_OPENAI_KEY]***`,
  },
  // Slack Token (Bot, User, Webhook)
  {
    name: 'Slack Token',
    regex: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b/g,
    mask: (match) => `${match.slice(0, 5)}***[REDACTED_SLACK_TOKEN]***`,
  },
  // Stripe Secret/Publishable Key
  {
    name: 'Stripe API Key',
    regex: /\b([rs]k_(?:live|test)_[0-9a-zA-Z]{24,99})\b/g,
    mask: (match) => `${match.slice(0, 8)}***[REDACTED_STRIPE_KEY]***`,
  },
  // Google Cloud / Firebase API Key
  {
    name: 'Google API Key',
    regex: /\b(AIza[0-9A-Za-z\\-_]{35})\b/g,
    mask: (match) => `${match.slice(0, 4)}***[REDACTED_GOOGLE_KEY]***`,
  },
  // Generic RSA / OpenSSH / EC Private Key
  {
    name: 'Private Key',
    regex:
      /(-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_-]+ PRIVATE KEY-----)/g,
    mask: () =>
      '-----BEGIN PRIVATE KEY-----\n***[REDACTED_PRIVATE_KEY]***\n-----END PRIVATE KEY-----',
  },
  // JWT Token format
  {
    name: 'JWT Token',
    regex: /\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    mask: () => 'eyJ***[REDACTED_JWT_TOKEN]***',
  },
  // Hardcoded password/secret assignment (e.g. password = "mysecretpassword123")
  {
    name: 'Generic Password Assignment',
    regex:
      /((?:password|passwd|secret|api_key|apikey|auth_token|token)\s*[:=]\s*["'])([^"'\r\n\s]{6,})(["'])/gi,
    mask: (_match, prefix, val, suffix) =>
      val.includes('[REDACTED') ? _match : `${prefix}***[REDACTED_SECRET]***${suffix}`,
  },
];

/**
 * Redacts all identified secrets and sensitive tokens from a string.
 * Also sanitizes terminal escape codes so the output is safe for display and logging.
 */
export function redactSensitiveData(input: string): string {
  if (typeof input !== 'string') return '';
  let result = input;

  for (const pattern of SECRET_PATTERNS) {
    // Reset regex state if global
    pattern.regex.lastIndex = 0;
    result = result.replace(pattern.regex, pattern.mask);
  }

  return sanitizeTerminalString(result);
}

/**
 * Calculates Shannon entropy of a given string.
 * Useful for detecting high-entropy random keys.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;

  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}
