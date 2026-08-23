import * as assert from "node:assert";

let passed = 0;
let failed = 0;

export function test(name: string, fn: () => void) {
  try {
    fn();
    passed++;
    console.log(`  ok - ${name}`);
  } catch (err: any) {
    failed++;
    console.log(`  FAIL - ${name}`);
    console.log(`    ${err.message}`);
  }
}

export function suite(name: string) {
  console.log(name);
}

export function finish() {
  console.log(`\n${passed} passed, ${failed} failed\n`);
  if (failed > 0) process.exit(1);
}

export { assert };
