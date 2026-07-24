// Emits N lines of "<base64 utf8 input>\t<base64 utf8 of JSON.stringify(input)>"
// for random I-JSON strings. Within that input domain, JSON.stringify's string
// serialization is the normative reference for RFC 8785 (Section 3.2.2.2).
// Surrogates and Unicode noncharacters are excluded by I-JSON (Section 2.1).
'use strict';

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

function isIJsonScalar(cp) {
  const isSurrogate = cp >= 0xd800 && cp <= 0xdfff;
  const isNoncharacter =
    (cp >= 0xfdd0 && cp <= 0xfdef) ||
    (cp & 0xffff) === 0xfffe ||
    (cp & 0xffff) === 0xffff;
  return !isSurrogate && !isNoncharacter;
}

function randomCodepoint(random = Math.random) {
  while (true) {
    const r = random();
    let cp;
    if (r < 0.25) {
      cp = Math.floor(random() * 0x80); // ASCII incl. controls
    } else if (r < 0.5) {
      cp = Math.floor(random() * 0x800); // Latin/Greek/etc.
    } else if (r < 0.85) {
      cp = Math.floor(random() * 0x10000); // BMP
    } else {
      cp = 0x10000 + Math.floor(random() * 0x100000); // astral
    }
    if (isIJsonScalar(cp)) return cp;
  }
}

function main() {
  const count = parsePositiveCount(process.argv[2], '20000');
  const lines = [];

  for (let i = 0; i < count; i++) {
    const len = Math.floor(Math.random() * 24);
    let s = '';
    for (let j = 0; j < len; j++) s += String.fromCodePoint(randomCodepoint());
    lines.push(
      Buffer.from(s, 'utf8').toString('base64') +
        '\t' +
        Buffer.from(JSON.stringify(s), 'utf8').toString('base64')
    );
  }

  process.stdout.write(lines.join('\n') + '\n');
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(error.message + '\n');
    process.exitCode = 1;
  }
}

module.exports = {isIJsonScalar, randomCodepoint};
