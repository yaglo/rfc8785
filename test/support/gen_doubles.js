// Emits N lines of "<ieee754-hex>\t<ES6 serialization>" for random finite
// doubles, plus fixed edge cases. The ES6 serialization (JSON.stringify)
// is the normative reference for RFC 8785 number formatting.
'use strict';
const crypto = require('crypto');

function parsePositiveCount(raw, fallback) {
  const text = raw === undefined ? fallback : raw;
  if (!/^[0-9]+$/.test(text)) {
    throw new Error('sample count must be a positive decimal integer');
  }

  const count = Number(text);
  if (!Number.isSafeInteger(count) || count <= 0) {
    throw new Error('sample count must be a positive decimal integer');
  }
  return count;
}

let N;
try {
  N = parsePositiveCount(process.argv[2], '100000');
} catch (error) {
  process.stderr.write(error.message + '\n');
  process.exit(1);
}

const buf = Buffer.alloc(8);
const lines = [];
let produced = 0;

while (produced < N) {
  crypto.randomFillSync(buf);
  if (produced % 2 === 0) {
    // Bias half the samples toward the exponent range where notation
    // switches happen (roughly 1e-10 .. 1e25).
    const expo = 1023 + Math.floor(Math.random() * 120) - 40;
    buf[0] = (buf[0] & 0x80) | (expo >> 4);
    buf[1] = (buf[1] & 0x0f) | ((expo & 0xf) << 4);
  }
  const v = buf.readDoubleBE(0);
  if (!Number.isFinite(v)) continue;
  lines.push(buf.toString('hex') + '\t' + JSON.stringify(v));
  produced++;
}

const edges = [
  0, 5e-324, -5e-324, 1.7976931348623157e308, -1.7976931348623157e308,
  9007199254740992, -9007199254740992, 1e21, 1e-7, 0.000001,
  9.999999999999997e-7, 999999999999999700000, 1424953923781206.2,
  0.001, 1e-4, 1.7e-5, 123.45, 2.5e-7, 2.5e-6,
];
for (const v of edges) {
  buf.writeDoubleBE(v, 0);
  lines.push(buf.toString('hex') + '\t' + JSON.stringify(v));
}

process.stdout.write(lines.join('\n') + '\n');
