import {
  buildSlackProviderUserId,
  createSignedSlackState,
  parseSignedSlackState,
  sanitizeRedirectPath,
} from './slack-auth.util';

describe('slack-auth.util', () => {
  it('sanitizes redirect paths', () => {
    expect(sanitizeRedirectPath('/home?x=1')).toBe('/home?x=1');
    expect(sanitizeRedirectPath('https://evil.example')).toBeNull();
    expect(sanitizeRedirectPath('//evil.example')).toBeNull();
    expect(sanitizeRedirectPath('/javascript:alert(1)')).toBeNull();
  });

  it('builds provider user id with team and user id', () => {
    expect(buildSlackProviderUserId('U123', 'T123')).toBe('T123:U123');
    expect(buildSlackProviderUserId('U123')).toBe('U123');
  });

  it('creates and parses signed state', () => {
    const state = createSignedSlackState({
      workspaceId: 'workspace-1',
      redirectPath: '/home',
      appSecret: 'x'.repeat(32),
    });

    const parsed = parseSignedSlackState(state, 'x'.repeat(32));
    expect(parsed).toMatchObject({
      workspaceId: 'workspace-1',
      redirectPath: '/home',
    });
  });
});
