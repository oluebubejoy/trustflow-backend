import { Injectable, Inject } from '@nestjs/common';
import { SanitizedLogger } from '../common/logging/sanitized-logger';
import { Redis } from 'ioredis';
import { REDIS_CLIENT } from '../common/redis/redis.module';
import * as crypto from 'crypto';

const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
const ACCESS_TOKEN_TTL_SECONDS = 3600; // 1 hour

@Injectable()
export class RefreshTokenStoreService {
  private readonly logger = new SanitizedLogger(RefreshTokenStoreService.name);
  private readonly inMemoryTokens = new Map<string, { issuedAt: number; familyId: string }>();
  private readonly inMemoryFamilies = new Map<string, Set<string>>();
  private readonly inMemoryActiveJti = new Map<string, { jti: string; expiresAt: number }>();

  private get redis(): Redis | null {
    return this.redisClient;
  }

  constructor(@Inject(REDIS_CLIENT) private readonly redisClient: Redis | null) {}

  async issueRefreshToken(
    address: string,
    familyId: string = crypto.randomBytes(16).toString('hex'),
  ): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const key = this.tokenKey(token);
    const familyKey = this.familyKey(address, familyId);

    if (this.redis) {
      try {
        await this.redis
          .multi()
          .set(
            key,
            JSON.stringify({ address, familyId, issuedAt: Date.now() }),
            'EX',
            REFRESH_TOKEN_TTL_SECONDS,
          )
          .sadd(familyKey, token)
          .expire(familyKey, REFRESH_TOKEN_TTL_SECONDS)
          .exec();
        return token;
      } catch (err) {
        this.logger.warn('Redis unavailable for refresh token issue, falling back to memory');
      }
    }

    this.inMemoryTokens.set(token, { issuedAt: Date.now(), familyId });
    let family = this.inMemoryFamilies.get(familyKey);
    if (!family) {
      family = new Set();
      this.inMemoryFamilies.set(familyKey, family);
    }
    family.add(token);

    return token;
  }

  async validateAndRotateRefreshToken(
    token: string,
    address: string,
  ): Promise<{ valid: boolean; newToken?: string; familyId?: string; shouldRevoke?: boolean }> {
    const key = this.tokenKey(token);
    const tombstoneKey = this.tombstoneKey(token);

    if (this.redis) {
      try {
        // Check if token is in tombstone (already rotated)
        const tombstone = await this.redis.get(tombstoneKey);
        if (tombstone) {
          // Token reuse detected! Revoke entire family
          const parsed = JSON.parse(tombstone);
          this.logger.warn(
            `Refresh token reuse detected for ${this.maskAddress(address)}, revoking family ${parsed.familyId}`,
          );
          await this.revokeTokenFamily(address, parsed.familyId);
          return { valid: false, shouldRevoke: true };
        }

        const data = await this.redis.getdel(key);
        if (!data) {
          return { valid: false };
        }

        const parsed = JSON.parse(data);
        if (parsed.address !== address) {
          this.logger.warn(
            `Address mismatch for token: expected ${this.maskAddress(address)}, got ${this.maskAddress(parsed.address)}`,
          );
          return { valid: false };
        }

        // Store tombstone for reuse detection (5 min window)
        await this.redis.set(tombstoneKey, data, 'EX', 300);

        const newToken = crypto.randomBytes(32).toString('hex');
        const newKey = this.tokenKey(newToken);
        const familyKey = this.familyKey(address, parsed.familyId);

        await this.redis
          .multi()
          .set(
            newKey,
            JSON.stringify({ address, familyId: parsed.familyId, issuedAt: Date.now() }),
            'EX',
            REFRESH_TOKEN_TTL_SECONDS,
          )
          .sadd(familyKey, newToken)
          .expire(familyKey, REFRESH_TOKEN_TTL_SECONDS)
          .exec();

        return { valid: true, newToken, familyId: parsed.familyId };
      } catch (err) {
        this.logger.warn('Redis unavailable for token validation, falling back to memory');
      }
    }

    const entry = this.inMemoryTokens.get(token);
    if (!entry) {
      return { valid: false };
    }

    if (entry.issuedAt + REFRESH_TOKEN_TTL_SECONDS * 1000 < Date.now()) {
      this.inMemoryTokens.delete(token);
      return { valid: false };
    }

    const newToken = crypto.randomBytes(32).toString('hex');
    const familyKey = this.familyKey(address, entry.familyId);
    const family = this.inMemoryFamilies.get(familyKey);

    if (!family) {
      // The key embeds the raw Stellar address; mask it rather than logging the composed key.
      this.logger.error(`Refresh-token family not found for address ${this.maskAddress(address)}`);
      return { valid: false };
    }

    this.inMemoryTokens.delete(token);
    this.inMemoryTokens.set(newToken, { issuedAt: Date.now(), familyId: entry.familyId });
    family.add(newToken);

    return { valid: true, newToken, familyId: entry.familyId };
  }

  /**
   * Records `jti` as the only valid access token for session `familyId` (#847). Issuing a new
   * access token on refresh overwrites it, so the previous access token is rejected.
   */
  async setActiveAccessJti(familyId: string, jti: string): Promise<void> {
    const key = this.activeJtiKey(familyId);

    if (this.redis) {
      try {
        await this.redis.set(key, jti, 'EX', ACCESS_TOKEN_TTL_SECONDS);
        return;
      } catch (err) {
        this.logger.warn('Redis unavailable for access token tracking, falling back to memory');
      }
    }

    this.inMemoryActiveJti.set(key, { jti, expiresAt: Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000 });
  }

  /** False only when a newer access token has been issued for the same session. */
  async isActiveAccessJti(familyId: string, jti: string): Promise<boolean> {
    const key = this.activeJtiKey(familyId);

    if (this.redis) {
      try {
        const active = await this.redis.get(key);
        return active === null || active === jti;
      } catch (err) {
        this.logger.warn('Redis unavailable for access token check, falling back to memory');
      }
    }

    const entry = this.inMemoryActiveJti.get(key);
    if (!entry || Date.now() > entry.expiresAt) return true;
    return entry.jti === jti;
  }

  async revokeRefreshToken(address: string, token: string): Promise<void> {
    const key = this.tokenKey(token);

    if (this.redis) {
      try {
        await this.redis.del(key);
        return;
      } catch (err) {
        this.logger.warn('Redis unavailable for token revocation, falling back to memory');
      }
    }

    this.inMemoryTokens.delete(token);
  }

  async revokeTokenFamily(address: string, familyId: string): Promise<void> {
    const familyKey = this.familyKey(address, familyId);

    if (this.redis) {
      try {
        const tokens = await this.redis.smembers(familyKey);
        if (tokens.length > 0) {
          const pipeline = this.redis.pipeline();
          tokens.forEach(t => pipeline.del(this.tokenKey(t)));
          pipeline.del(familyKey);
          await pipeline.exec();
        }
        return;
      } catch (err) {
        this.logger.warn('Redis unavailable for family revocation, falling back to memory');
      }
    }

    const family = this.inMemoryFamilies.get(familyKey);
    if (family) {
      family.forEach(t => this.inMemoryTokens.delete(t));
      this.inMemoryFamilies.delete(familyKey);
    }
  }

  private tokenKey(token: string): string {
    return `refresh-token:${token}`;
  }

  private activeJtiKey(familyId: string): string {
    return `access-jti:${familyId}`;
  }

  private tombstoneKey(token: string): string {
    return `refresh-tombstone:${token}`;
  }

  private familyKey(address: string, familyId: string): string {
    return `refresh-family:${address}:${familyId}`;
  }

  private maskAddress(address: string): string {
    if (address.length <= 12) return '****';
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }
}

export { REFRESH_TOKEN_TTL_SECONDS, ACCESS_TOKEN_TTL_SECONDS };
