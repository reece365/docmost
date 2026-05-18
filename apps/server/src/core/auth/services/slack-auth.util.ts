import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

type SlackStatePayload = {
  workspaceId: string;
  redirectPath: string | null;
  nonce: string;
  ts: number;
};

const SLACK_STATE_MAX_AGE_MILLISECONDS = 10 * 60 * 1000;

function base64UrlEncode(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64url');
}

function base64UrlDecode(input: string): string {
  return Buffer.from(input, 'base64url').toString('utf8');
}

export function sanitizeRedirectPath(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  if (input.length === 0 || input.length > 2048) return null;
  if (!input.startsWith('/') || input.startsWith('//')) return null;
  if (input.toLowerCase().includes('://')) return null;
  if (/^\/[a-z][a-z0-9+\-.]*:/i.test(input)) return null;
  if (/[\s\\]|\p{C}/u.test(input)) return null;

  return input;
}

export function buildSlackProviderUserId(
  slackUserId: string,
  slackTeamId?: string | null,
): string {
  return slackTeamId ? `${slackTeamId}:${slackUserId}` : slackUserId;
}

function signState(payloadBase64: string, appSecret: string): string {
  return createHmac('sha256', appSecret).update(payloadBase64).digest('base64url');
}

export function createSignedSlackState(opts: {
  workspaceId: string;
  redirectPath?: string | null;
  appSecret: string;
}): string {
  const payload: SlackStatePayload = {
    workspaceId: opts.workspaceId,
    redirectPath: sanitizeRedirectPath(opts.redirectPath) ?? null,
    nonce: randomUUID(),
    ts: Date.now(),
  };

  const payloadBase64 = base64UrlEncode(JSON.stringify(payload));
  const signature = signState(payloadBase64, opts.appSecret);
  return `${payloadBase64}.${signature}`;
}

export function parseSignedSlackState(
  signedState: string,
  appSecret: string,
): SlackStatePayload | null {
  const [payloadBase64, providedSignature] = (signedState || '').split('.');
  if (!payloadBase64 || !providedSignature) return null;

  const expectedSignature = signState(payloadBase64, appSecret);
  if (providedSignature.length !== expectedSignature.length) return null;
  const isValid = timingSafeEqual(
    Buffer.from(providedSignature),
    Buffer.from(expectedSignature),
  );
  if (!isValid) return null;

  let payload: SlackStatePayload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadBase64));
  } catch {
    return null;
  }

  if (!payload.workspaceId || typeof payload.workspaceId !== 'string') return null;
  if (!payload.ts || typeof payload.ts !== 'number') return null;
  if (Date.now() - payload.ts > SLACK_STATE_MAX_AGE_MILLISECONDS) return null;

  return {
    workspaceId: payload.workspaceId,
    redirectPath: sanitizeRedirectPath(payload.redirectPath),
    nonce: payload.nonce,
    ts: payload.ts,
  };
}
