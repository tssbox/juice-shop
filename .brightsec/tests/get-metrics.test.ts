import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('GET /metrics', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['improper_asset_management', 'csrf', 'full_path_disclosure', 'open_database', 'secret_tokens'],
      attackParamLocations: [AttackParamLocation.HEADER],
      starMetadata: {
        code_source: "tssbox/juice-shop:master",
        databases: ["SQLite"],
        user_roles: {
          roles: ["customer", "deluxe", "accounting", "admin"]
        }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/metrics`,
      headers: { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});