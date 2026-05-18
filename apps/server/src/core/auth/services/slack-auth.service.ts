import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectKysely } from 'nestjs-kysely';
import { KyselyDB } from '@docmost/db/types/kysely.types';
import { User, Workspace } from '@docmost/db/types/entity.types';
import { EnvironmentService } from '../../../integrations/environment/environment.service';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { SignupService } from './signup.service';
import { SessionService } from '../../session/session.service';
import { executeTx } from '@docmost/db/utils';
import { isUserDisabled, nanoIdGen } from '../../../common/helpers';
import { validateAllowedEmail } from '../auth.util';
import {
  buildSlackProviderUserId,
  createSignedSlackState,
  parseSignedSlackState,
} from './slack-auth.util';

type SlackOpenIdTokenResponse = {
  ok?: boolean;
  error?: string;
  access_token?: string;
};

type SlackOpenIdUserInfoResponse = {
  sub?: string;
  email?: string;
  name?: string;
  ['https://slack.com/team_id']?: string;
};

@Injectable()
export class SlackAuthService {
  constructor(
    private readonly environmentService: EnvironmentService,
    private readonly userRepo: UserRepo,
    private readonly signupService: SignupService,
    private readonly sessionService: SessionService,
    @InjectKysely() private readonly db: KyselyDB,
  ) {}

  getAuthorizationUrl(workspace: Workspace, redirectPath?: string | null): string {
    if (!this.environmentService.isSlackAuthEnabled()) {
      throw new ForbiddenException('Slack sign-in is not configured.');
    }

    const clientId = this.environmentService.getSlackClientId();
    const redirectUri = this.environmentService.getSlackRedirectUrl();
    const state = createSignedSlackState({
      workspaceId: workspace.id,
      redirectPath,
      appSecret: this.environmentService.getAppSecret(),
    });

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid profile email',
      state,
    });

    return `https://slack.com/openid/connect/authorize?${params.toString()}`;
  }

  async signInWithCallback(opts: {
    code: string;
    state: string;
    workspace: Workspace;
  }): Promise<{ authToken: string; redirectPath: string | null }> {
    if (!opts.code || !opts.state) {
      throw new BadRequestException('Missing Slack authorization callback data.');
    }

    if (!this.environmentService.isSlackAuthEnabled()) {
      throw new ForbiddenException('Slack sign-in is not configured.');
    }

    const parsedState = parseSignedSlackState(
      opts.state,
      this.environmentService.getAppSecret(),
    );
    if (!parsedState || parsedState.workspaceId !== opts.workspace.id) {
      throw new UnauthorizedException('Invalid Slack state.');
    }

    const tokenData = await this.exchangeCodeForToken(opts.code);
    const userInfo = await this.getUserInfo(tokenData.access_token);
    const slackUserId = userInfo.sub;
    const slackTeamId = userInfo['https://slack.com/team_id'] ?? null;
    const email = userInfo.email?.toLowerCase();

    if (!email) {
      throw new BadRequestException(
        'Slack account did not provide an email address.',
      );
    }

    if (!slackUserId) {
      throw new UnauthorizedException('Slack user id is missing.');
    }

    validateAllowedEmail(email, opts.workspace);
    const providerUserId = buildSlackProviderUserId(slackUserId, slackTeamId);
    const user = await this.findOrCreateSlackUser({
      workspace: opts.workspace,
      providerUserId,
      email,
      displayName: userInfo.name,
    });

    if (isUserDisabled(user)) {
      throw new UnauthorizedException('Account is disabled.');
    }

    await this.userRepo.updateLastLogin(user.id, user.workspaceId);
    const authToken = await this.sessionService.createSessionAndToken(user);

    return {
      authToken,
      redirectPath: parsedState.redirectPath,
    };
  }

  private async exchangeCodeForToken(
    code: string,
  ): Promise<Required<Pick<SlackOpenIdTokenResponse, 'access_token'>>> {
    const params = new URLSearchParams({
      client_id: this.environmentService.getSlackClientId(),
      client_secret: this.environmentService.getSlackClientSecret(),
      code,
      redirect_uri: this.environmentService.getSlackRedirectUrl(),
      grant_type: 'authorization_code',
    });

    const response = await fetch('https://slack.com/api/openid.connect.token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
    });

    const tokenData = (await response.json()) as SlackOpenIdTokenResponse;
    if (!response.ok || !tokenData?.ok || !tokenData.access_token) {
      throw new UnauthorizedException(
        tokenData?.error || 'Slack token exchange failed.',
      );
    }

    return { access_token: tokenData.access_token };
  }

  private async getUserInfo(accessToken: string): Promise<SlackOpenIdUserInfoResponse> {
    const response = await fetch('https://slack.com/api/openid.connect.userInfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new UnauthorizedException('Failed to fetch Slack profile.');
    }

    return (await response.json()) as SlackOpenIdUserInfoResponse;
  }

  private async findOrCreateSlackUser(opts: {
    workspace: Workspace;
    providerUserId: string;
    email: string;
    displayName?: string;
  }): Promise<User> {
    return executeTx(this.db, async (trx) => {
      const existingAccount = await trx
        .selectFrom('authAccounts')
        .select(['userId'])
        .where('workspaceId', '=', opts.workspace.id)
        .where('providerUserId', '=', opts.providerUserId)
        .where('authProviderId', 'is', null)
        .executeTakeFirst();

      if (existingAccount?.userId) {
        const user = await this.userRepo.findById(existingAccount.userId, opts.workspace.id, {
          trx,
        });
        if (user) return user;
      }

      let user = await this.userRepo.findByEmail(opts.email, opts.workspace.id, {
        trx,
      });

      if (!user) {
        user = await this.signupService.signup(
          {
            email: opts.email,
            name: opts.displayName || opts.email.split('@')[0],
            password: `slack-${nanoIdGen()}A1!`,
          },
          opts.workspace.id,
          trx,
        );

        await this.userRepo.updateUser(
          {
            hasGeneratedPassword: true,
            emailVerifiedAt: new Date(),
          },
          user.id,
          opts.workspace.id,
          trx,
        );
      }

      const linkedAccount = await trx
        .selectFrom('authAccounts')
        .select('id')
        .where('workspaceId', '=', opts.workspace.id)
        .where('userId', '=', user.id)
        .where('providerUserId', '=', opts.providerUserId)
        .where('authProviderId', 'is', null)
        .executeTakeFirst();

      if (!linkedAccount) {
        await trx
          .insertInto('authAccounts')
          .values({
            userId: user.id,
            workspaceId: opts.workspace.id,
            providerUserId: opts.providerUserId,
            authProviderId: null,
          })
          .execute();
      }

      return user;
    });
  }
}
