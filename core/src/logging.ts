// Structured, togglable logger. The CLAUDE.md rule bans `console.log` —
// every package writes through here. Levels are ordered numerically so
// runtime comparison is cheap; output is JSON so log shippers can parse it.

export const LOG_LEVELS = ['silent', 'error', 'warn', 'info', 'debug', 'trace'] as const;

export type LogLevel = (typeof LOG_LEVELS)[number];

const LEVEL_RANK: Readonly<Record<LogLevel, number>> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
  trace: 5,
};

export interface LogRecord {
  readonly ts: string;
  readonly level: Exclude<LogLevel, 'silent'>;
  readonly scope: string;
  readonly msg: string;
  readonly fields?: Readonly<Record<string, unknown>>;
}

export type LogSink = (record: LogRecord) => void;

export interface Logger {
  readonly level: LogLevel;
  child(scope: string, fields?: Readonly<Record<string, unknown>>): Logger;
  error(msg: string, fields?: Readonly<Record<string, unknown>>): void;
  warn(msg: string, fields?: Readonly<Record<string, unknown>>): void;
  info(msg: string, fields?: Readonly<Record<string, unknown>>): void;
  debug(msg: string, fields?: Readonly<Record<string, unknown>>): void;
  trace(msg: string, fields?: Readonly<Record<string, unknown>>): void;
}

export interface LoggerOptions {
  readonly level?: LogLevel;
  readonly scope?: string;
  readonly sink?: LogSink;
  readonly baseFields?: Readonly<Record<string, unknown>>;
  readonly clock?: () => Date;
}

export const stderrSink: LogSink = (record) => {
  // process.stderr is allowed because it bypasses no-console and gives us
  // a write path that won't interfere with stdout-based CLI output.
  process.stderr.write(`${JSON.stringify(record)}\n`);
};

export function createLogger(options: LoggerOptions = {}): Logger {
  const level: LogLevel = options.level ?? envLevel() ?? 'info';
  const scope = options.scope ?? 'vitonomi';
  const sink = options.sink ?? stderrSink;
  const baseFields = options.baseFields;
  const clock = options.clock ?? (() => new Date());
  const threshold = LEVEL_RANK[level];

  function emit(
    recordLevel: Exclude<LogLevel, 'silent'>,
    msg: string,
    fields?: Readonly<Record<string, unknown>>,
  ): void {
    if (LEVEL_RANK[recordLevel] > threshold) return;
    const merged = mergeFields(baseFields, fields);
    const record: LogRecord = merged
      ? { ts: clock().toISOString(), level: recordLevel, scope, msg, fields: merged }
      : { ts: clock().toISOString(), level: recordLevel, scope, msg };
    sink(record);
  }

  return {
    level,
    child(childScope, childFields) {
      const merged = mergeFields(baseFields, childFields);
      const opts: LoggerOptions = {
        level,
        scope: `${scope}:${childScope}`,
        sink,
        clock,
      };
      return createLogger(merged ? { ...opts, baseFields: merged } : opts);
    },
    error: (m, f) => emit('error', m, f),
    warn: (m, f) => emit('warn', m, f),
    info: (m, f) => emit('info', m, f),
    debug: (m, f) => emit('debug', m, f),
    trace: (m, f) => emit('trace', m, f),
  };
}

function mergeFields(
  a: Readonly<Record<string, unknown>> | undefined,
  b: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, unknown>> | undefined {
  if (!a) return b;
  if (!b) return a;
  return { ...a, ...b };
}

function envLevel(): LogLevel | undefined {
  const raw = process.env['VITONOMI_LOG_LEVEL'];
  if (!raw) return undefined;
  const candidate = raw.toLowerCase();
  return (LOG_LEVELS as readonly string[]).includes(candidate)
    ? (candidate as LogLevel)
    : undefined;
}
