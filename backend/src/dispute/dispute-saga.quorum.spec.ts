import { Test } from '@nestjs/testing';
import { BadRequestException, ConflictException } from '@nestjs/common';
import { DisputeSagaService, DISPUTE_VOTING_WINDOW_MS } from './dispute-saga.service';
import { DisputeStep, DisputeVerdict } from './dispute.types';
import { EscrowService } from '../escrow/escrow.service';
import { WebhookService } from '../webhook/webhook.service';
import { NotificationService } from '../notification/notification.service';
import { REDIS_CLIENT } from '../common/redis/redis.module';
import { MetricsService } from '../monitoring/metrics.service';
import { ArweaveArchiveService } from './arweave-archive.service';

const JURORS = [
  'GJUROR1111111111111111111111111111111111111111111111111111',
  'GJUROR2222222222222222222222222222222222222222222222222222',
  'GJUROR3333333333333333333333333333333333333333333333333333',
  'GJUROR4444444444444444444444444444444444444444444444444444',
  'GJUROR5555555555555555555555555555555555555555555555555555',
];

/** Minimal in-memory stand-in for the ioredis calls the saga makes. */
function fakeRedis() {
  const kv = new Map<string, string>();
  const sets = new Map<string, Set<string>>();
  const multi = () => {
    const ops: Array<() => unknown> = [];
    const chain = {
      set: (k: string, v: string) => (ops.push(() => kv.set(k, v)), chain),
      sadd: (k: string, v: string) => (ops.push(() => (sets.get(k) ?? sets.set(k, new Set()).get(k)!).add(v)), chain),
      exec: async () => ops.map(op => [null, op()]),
    };
    return chain;
  };
  return {
    get: jest.fn(async (k: string) => kv.get(k) ?? null),
    mget: jest.fn(async (...ks: string[]) => ks.map(k => kv.get(k) ?? null)),
    smembers: jest.fn(async (k: string) => [...(sets.get(k) ?? [])]),
    set: jest.fn(async (k: string, v: string, ...args: unknown[]) => {
      if (args.includes('NX') && kv.has(k)) return null;
      kv.set(k, v);
      return 'OK';
    }),
    del: jest.fn(async (k: string) => (kv.delete(k) ? 1 : 0)),
    multi: jest.fn(multi),
  };
}

async function build(redis: unknown) {
  const escrow = {
    id: 'esc-001',
    depositor: 'GDEPOSITOR111111111111111111111111111111111111111111111',
    beneficiary: 'GBENEFICIARY1111111111111111111111111111111111111111111',
    amountXLM: '100',
    status: 'active',
    createdAt: new Date().toISOString(),
  };
  const escrowService = {
    findById: jest.fn().mockResolvedValue(escrow),
    findAll: jest.fn().mockResolvedValue([escrow]),
    raiseDispute: jest.fn().mockResolvedValue({ ...escrow, status: 'disputed' }),
    release: jest.fn().mockResolvedValue(escrow),
    cancel: jest.fn().mockResolvedValue(escrow),
    split: jest.fn().mockResolvedValue(escrow),
    correctStatus: jest.fn().mockResolvedValue(escrow),
  };
  const webhookService = { dispatch: jest.fn().mockResolvedValue(undefined) };
  const module = await Test.createTestingModule({
    providers: [
      DisputeSagaService,
      { provide: EscrowService, useValue: escrowService },
      { provide: WebhookService, useValue: webhookService },
      { provide: NotificationService, useValue: { notifyDisputeEscalation: jest.fn().mockResolvedValue(undefined) } },
      { provide: REDIS_CLIENT, useValue: redis },
      { provide: MetricsService, useValue: { increment: jest.fn() } },
      { provide: ArweaveArchiveService, useValue: { archiveDispute: jest.fn().mockResolvedValue(undefined) } },
    ],
  }).compile();
  return { service: module.get(DisputeSagaService), escrowService };
}

async function sagaInVoting(service: DisputeSagaService) {
  const saga = await service.escalate('esc-001', {
    initiator: 'GDEPOSITOR111111111111111111111111111111111111111111111',
    reason: 'Work was not delivered as agreed in the contract',
  });
  await service.assignJurors(saga.sagaId, { jurors: JURORS });
  return saga.sagaId;
}

describe('DisputeSagaService quorum, sweep and payout claim', () => {
  it('sets a voting deadline when jurors are assigned', async () => {
    const { service } = await build(null);
    const sagaId = await sagaInVoting(service);
    const saga = await service.findById(sagaId);
    expect(saga.votingDeadline).toBeDefined();
  });

  it('refuses to finalize below quorum of assigned jurors (#853)', async () => {
    const { service } = await build(null);
    const sagaId = await sagaInVoting(service);
    await service.castVote(sagaId, { jurorAddress: JURORS[0]!, vote: 'beneficiary' });
    await service.castVote(sagaId, { jurorAddress: JURORS[1]!, vote: 'beneficiary' });

    await expect(service.finalizeVoting(sagaId)).rejects.toThrow(BadRequestException);
    expect((await service.findById(sagaId)).currentStep).toBe(DisputeStep.VOTING);
  });

  it('finalizes from persisted votes once quorum is reached (#852)', async () => {
    const { service } = await build(fakeRedis());
    const sagaId = await sagaInVoting(service);
    for (const juror of JURORS.slice(0, 3)) {
      await service.castVote(sagaId, { jurorAddress: juror, vote: 'beneficiary' });
    }

    const saga = await service.finalizeVoting(sagaId);
    expect(saga.verdict).toBe(DisputeVerdict.BENEFICIARY_WINS);
    expect(saga.currentStep).toBe(DisputeStep.PAYOUT);
  });

  it('sweep finalizes only expired sagas that reached quorum (#855)', async () => {
    const { service } = await build(null);
    const sagaId = await sagaInVoting(service);
    for (const juror of JURORS.slice(0, 3)) {
      await service.castVote(sagaId, { jurorAddress: juror, vote: 'depositor' });
    }

    expect(await service.sweepExpiredVoting(new Date())).toBe(0);
    const later = new Date(Date.now() + DISPUTE_VOTING_WINDOW_MS + 1000);
    expect(await service.sweepExpiredVoting(later)).toBe(1);
    expect((await service.findById(sagaId)).verdict).toBe(DisputeVerdict.DEPOSITOR_WINS);
  });

  it('only one of two parallel payout requests submits a payout (#854)', async () => {
    const redis = fakeRedis();
    const { service, escrowService } = await build(redis);
    const sagaId = await sagaInVoting(service);
    for (const juror of JURORS) {
      await service.castVote(sagaId, { jurorAddress: juror, vote: 'beneficiary' });
    }
    // Simulate another instance already holding the payout claim.
    await redis.set(`saga:payout-claim:${sagaId}`, '1', 'PX', 1000, 'NX');

    await expect(service.executePayout(sagaId, {})).rejects.toThrow(ConflictException);
    expect(escrowService.release).not.toHaveBeenCalled();
  });
});
