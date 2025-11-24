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

test('POST /api/products', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['xss', 'bopla', 'sqli', 'csrf', 'file_upload'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'tssbox/juice-shop:master',
        databases: ['SQLite'],
        user_roles: {
          roles: ['customer', 'deluxe', 'accounting', 'admin']
        }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Products`,
      body: {
        name: 'Sample Product',
        description: 'A sample product description.',
        price: 19.99,
        deluxePrice: 29.99,
        image: 'sample-image.png'
      },
      headers: {
        'Content-Type': 'application/json',
        'X-Recruiting': '<recruiting_info_here>'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});