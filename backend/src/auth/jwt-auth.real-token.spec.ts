import { Controller, Get, INestApplication, Req, UseGuards } from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { JwtAuthGuard } from './auth.guard';
import { JwtStrategy } from './jwt.strategy';
import { JWT_ALGORITHM, setTestEnv } from '../config/env.config';
import { Keypair } from '@stellar/stellar-sdk';
import { RefreshTokenStoreService } from './refresh-token-store.service';
import { REDIS_CLIENT } from '../common/redis/redis.constants';

const ADDRESS = Keypair.random().publicKey();

@Controller('protected')
class ProtectedController {
  @Get()
  @UseGuards(JwtAuthGuard)
  getProtected(@Req() req: { user: { address: string; sub: string } }) {
    return req.user;
  }
}

describe('JwtAuthGuard and JwtStrategy real-token flow', () => {
  let app: INestApplication;
  let jwtService: JwtService;
  let refreshTokenStore: RefreshTokenStoreService;

  beforeEach(async () => {
    setTestEnv({
      NODE_ENV: 'test',
      JWT_SECRET: 'real-token-test-secret-at-least-16-chars',
    });

    const moduleRef = await Test.createTestingModule({
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          secret: 'real-token-test-secret-at-least-16-chars',
          signOptions: { algorithm: JWT_ALGORITHM, expiresIn: '1h' },
        }),
      ],
      controllers: [ProtectedController],
      providers: [
        JwtStrategy,
        RefreshTokenStoreService,
        { provide: REDIS_CLIENT, useValue: null },
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();
    jwtService = moduleRef.get(JwtService);
    refreshTokenStore = moduleRef.get(RefreshTokenStoreService);
  });

  afterEach(async () => {
    await app.close();
  });

  it('accepts a real HS256 token and exposes the validated user', async () => {
    const token = jwtService.sign({
      address: ADDRESS,
      sub: ADDRESS,
    });

    await request(app.getHttpServer())
      .get('/protected')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect({ address: ADDRESS, sub: ADDRESS });
  });

  it('rejects a token signed with a different HMAC algorithm', async () => {
    const token = jwtService.sign(
      { address: ADDRESS, sub: ADDRESS },
      { algorithm: 'HS384' },
    );

    await request(app.getHttpServer())
      .get('/protected')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);
  });

  // #846: a malformed wallet claim must be a 401, never a 500.
  it('rejects a token whose wallet claim is not a valid Stellar public key with 401', async () => {
    const token = jwtService.sign({ address: 'not-a-key', sub: 'not-a-key' });

    await request(app.getHttpServer())
      .get('/protected')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);
  });

  // #847: once a refresh issues a new access token for the session, the old one is rejected.
  it('rejects an access token superseded by a refresh of the same session', async () => {
    await refreshTokenStore.setActiveAccessJti('session-1', 'jti-a');
    const tokenA = jwtService.sign({ address: ADDRESS, sub: ADDRESS, sid: 'session-1', jti: 'jti-a' });

    await request(app.getHttpServer())
      .get('/protected')
      .set('Authorization', `Bearer ${tokenA}`)
      .expect(200);

    await refreshTokenStore.setActiveAccessJti('session-1', 'jti-b');
    const tokenB = jwtService.sign({ address: ADDRESS, sub: ADDRESS, sid: 'session-1', jti: 'jti-b' });

    await request(app.getHttpServer())
      .get('/protected')
      .set('Authorization', `Bearer ${tokenA}`)
      .expect(401);
    await request(app.getHttpServer())
      .get('/protected')
      .set('Authorization', `Bearer ${tokenB}`)
      .expect(200);
  });
});
