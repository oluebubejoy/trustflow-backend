import { HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { SanitizedLogger } from '../common/logging/sanitized-logger';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import * as StellarSdk from '@stellar/stellar-sdk';
import { config, getJwtVerificationSecrets } from '../config/env.config';
import { NonceStoreService, NONCE_TTL_SECONDS } from './nonce-store.service';
import { JWT_ALGORITHM } from '../config/env.config';
import { RefreshTokenStoreService, ACCESS_TOKEN_TTL_SECONDS } from './refresh-token-store.service';

const CHALLENGE_PREFIX = 'Sign this message to authenticate with TrustFlow: ';

@Injectable()
export class AuthService {
  private readonly logger = new SanitizedLogger(AuthService.name);

  constructor(
    private jwtService: JwtService,
    private nonceStore: NonceStoreService,
    private refreshTokenStore: RefreshTokenStoreService,
  ) {}

  async generateChallenge(address: string): Promise<string> {
    // Per-wallet limit (#993), independent of the caller's IP — see NonceStoreService.
    const rateLimit = await this.nonceStore.checkWalletChallengeRateLimit(
      address,
      config.AUTH_CHALLENGE_WALLET_RATE_LIMIT_POINTS,
      config.AUTH_CHALLENGE_WALLET_RATE_LIMIT_DURATION,
    );
    if (!rateLimit.allowed) {
      this.logger.warn(`Challenge rate limit exceeded for wallet ${this.maskAddress(address)}`);
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: 'Too many challenge requests for this wallet address',
          retryAfter: rateLimit.retryAfter,
          scope: `wallet:${this.maskAddress(address)}`,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const nonce = crypto.randomBytes(32).toString('hex');
    // #845: the expiry is part of the signed message and checked in verifySignature, so
    // acceptance doesn't rely solely on the Redis key's TTL being enforced on time.
    const expiresAt = Math.floor(Date.now() / 1000) + NONCE_TTL_SECONDS;
    const challenge = `${CHALLENGE_PREFIX}${nonce}:${expiresAt}`;

    // The store hands back an already-pending challenge rather than replacing it (#369).
    const active = (await this.nonceStore.store(address, challenge, nonce)) ?? challenge;
    this.logger.debug(`Challenge issued for ${this.maskAddress(address)}`);

    return active;
  }

  async verifySignature(address: string, signature: string): Promise<boolean> {
    const challenge = await this.nonceStore.consume(address);
    if (!challenge) {
      throw new UnauthorizedException('Challenge not found, expired, or already consumed');
    }

    const nonce = this.extractNonce(challenge);
    const expiresAt = this.extractExpiry(challenge);
    if (expiresAt !== null && Date.now() > expiresAt * 1000) {
      throw new UnauthorizedException('Challenge expired');
    }

    try {
      const signatureBuffer = Buffer.from(signature, 'base64');
      const challengeBuffer = Buffer.from(challenge, 'utf-8');

      const keypair = StellarSdk.Keypair.fromPublicKey(address);
      const isValid = keypair.verify(challengeBuffer, signatureBuffer);

      if (isValid && nonce) {
        const firstUse = await this.nonceStore.markNonceUsed(nonce);
        if (!firstUse) {
          this.logger.warn(`Replay attempt detected for ${this.maskAddress(address)}`);
          throw new UnauthorizedException('Challenge already used — replay blocked');
        }
        this.logger.debug(`Signature verified for ${this.maskAddress(address)}`);
      }

      return isValid;
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;
      this.logger.warn(
        `Signature verification failed for ${this.maskAddress(address)}: ${error instanceof Error ? error.message : 'unknown'}`,
      );
      throw new UnauthorizedException('Invalid signature');
    }
  }

  generateToken(
    address: string,
    ttlSeconds?: number,
    session?: { sid: string; jti: string },
  ): string {
    const payload = session ? { address, sub: address, ...session } : { address, sub: address };
    const options = ttlSeconds ? { expiresIn: ttlSeconds } : {};
    return this.jwtService.sign(payload, options);
  }

  async generateRefreshToken(address: string): Promise<string> {
    return this.refreshTokenStore.issueRefreshToken(address);
  }

  /**
   * Issues a refresh token and an access token bound to the same session (#847), so a later
   * refresh supersedes this access token instead of minting an independent sibling.
   */
  async issueSession(address: string): Promise<{ token: string; refreshToken: string }> {
    const sid = crypto.randomBytes(16).toString('hex');
    const refreshToken = await this.refreshTokenStore.issueRefreshToken(address, sid);
    const token = await this.issueSessionAccessToken(address, sid);
    return { token, refreshToken };
  }

  private async issueSessionAccessToken(address: string, sid: string): Promise<string> {
    const jti = crypto.randomBytes(16).toString('hex');
    await this.refreshTokenStore.setActiveAccessJti(sid, jti);
    return this.generateToken(address, ACCESS_TOKEN_TTL_SECONDS, { sid, jti });
  }

  async refreshAccessToken(
    refreshToken: string,
    address: string,
  ): Promise<{ token: string; refreshToken: string } | null> {
    const result = await this.refreshTokenStore.validateAndRotateRefreshToken(
      refreshToken,
      address,
    );
    if (!result.valid || !result.newToken || !result.familyId) {
      return null;
    }

    const newAccessToken = await this.issueSessionAccessToken(address, result.familyId);
    return {
      token: newAccessToken,
      refreshToken: result.newToken,
    };
  }

  async revokeRefreshToken(address: string, token: string): Promise<void> {
    return this.refreshTokenStore.revokeRefreshToken(address, token);
  }

  validateToken(token: string): unknown {
    try {
      return this.jwtService.verify(token, { algorithms: [JWT_ALGORITHM] });
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractNonce(challenge: string): string | null {
    if (!challenge.startsWith(CHALLENGE_PREFIX)) return null;
    return challenge.slice(CHALLENGE_PREFIX.length).split(':')[0];
  }

  /** Expiry (unix seconds) embedded in the challenge, or null if the challenge has none. */
  private extractExpiry(challenge: string): number | null {
    if (!challenge.startsWith(CHALLENGE_PREFIX)) return null;
    const expiry = challenge.slice(CHALLENGE_PREFIX.length).split(':')[1];
    if (expiry === undefined) return null;
    const value = Number(expiry);
    return Number.isFinite(value) ? value : 0;
  }

  private maskAddress(address: string): string {
    if (address.length <= 12) return '****';
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }
}
