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

test('POST /api/challenges', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'sqli'],
      attackParamLocations: [AttackParamLocation.BODY],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Challenges`,
      body: {
        id: 1,
        key: "restfulXssChallenge",
        name: "Sample Challenge",
        category: "Security",
        description: "A sample challenge description.",
        difficulty: 3,
        mitigationUrl: "http://example.com/mitigation",
        solved: false,
        disabledEnv: null,
        tutorialOrder: null,
        tags: "sample,challenge",
        codingChallengeStatus: 0,
        hasCodingChallenge: false
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});