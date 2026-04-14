import { describe, expect, it } from 'vitest';

import { createLogger, type LogRecord } from '../src/logging.js';

describe('createLogger', () => {
  function captureSink(): { records: LogRecord[]; sink: (r: LogRecord) => void } {
    const records: LogRecord[] = [];
    return { records, sink: (r) => records.push(r) };
  }

  const fixedClock = (): Date => new Date('2026-04-14T00:00:00.000Z');

  it('emits records at or below the configured level', () => {
    const { records, sink } = captureSink();
    const log = createLogger({ level: 'info', sink, clock: fixedClock, scope: 'test' });

    log.error('boom');
    log.warn('careful');
    log.info('hi');
    log.debug('quiet');
    log.trace('quieter');

    expect(records.map((r) => r.level)).toEqual(['error', 'warn', 'info']);
    expect(records[0]).toMatchObject({
      level: 'error',
      msg: 'boom',
      scope: 'test',
      ts: '2026-04-14T00:00:00.000Z',
    });
  });

  it('silences everything at level=silent', () => {
    const { records, sink } = captureSink();
    const log = createLogger({ level: 'silent', sink });
    log.error('nope');
    log.info('also nope');
    expect(records).toEqual([]);
  });

  it('merges base fields with per-call fields', () => {
    const { records, sink } = captureSink();
    const log = createLogger({
      level: 'debug',
      sink,
      scope: 'svc',
      baseFields: { reqId: 'r-1' },
      clock: fixedClock,
    });
    log.info('done', { ms: 12 });
    expect(records[0]?.fields).toEqual({ reqId: 'r-1', ms: 12 });
  });

  it('child() extends scope and merges fields', () => {
    const { records, sink } = captureSink();
    const parent = createLogger({
      level: 'debug',
      sink,
      scope: 'svc',
      baseFields: { reqId: 'r-1' },
      clock: fixedClock,
    });
    const child = parent.child('upload', { photoId: 'p-9' });

    child.debug('chunked', { chunks: 3 });

    expect(records[0]).toMatchObject({
      scope: 'svc:upload',
      fields: { reqId: 'r-1', photoId: 'p-9', chunks: 3 },
    });
  });

  it('omits fields key when there are no fields', () => {
    const { records, sink } = captureSink();
    const log = createLogger({ level: 'info', sink, clock: fixedClock });
    log.info('plain');
    expect(records[0]).not.toHaveProperty('fields');
  });
});
