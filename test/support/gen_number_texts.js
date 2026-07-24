// Emits N random records plus fixed edge records as
// "<JSON number token>\t<JSON.stringify(JSON.parse(token))>".
//
// This exercises decimal-text parsing separately from gen_doubles.js, which
// starts with an already parsed IEEE-754 value. Inputs whose parsed result is
// negative zero are omitted: RFC 8785 erratum 7920 recommends
// rejecting those at parse time, and the Elixir test covers that separately.
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

function randomInt(limit) {
  return Math.floor(Math.random() * limit);
}

function digits(length, nonzeroFirst = false) {
  let result = nonzeroFirst ? String(1 + randomInt(9)) : String(randomInt(10));
  for (let i = 1; i < length; i++) result += String(randomInt(10));
  return result;
}

function sign() {
  return randomInt(2) === 0 ? '' : '-';
}

function exponent(min, max, maxLeadingZeros = 12) {
  const value = min + randomInt(max - min + 1);
  const marker = randomInt(2) === 0 ? 'e' : 'E';
  const explicitSign = value < 0 ? '-' : randomInt(2) === 0 ? '' : '+';
  const magnitude = String(Math.abs(value)).padStart(
    String(Math.abs(value)).length + randomInt(maxLeadingZeros + 1),
    '0'
  );
  return marker + explicitSign + magnitude;
}

function randomLexeme() {
  const prefix = sign();

  switch (randomInt(6)) {
    case 0:
      // Exact integer tokens stay within the range where decimal digits are
      // preserved by the parser and by RFC8785's strict integer policy.
      return prefix + digits(1 + randomInt(15), true);

    case 1:
      return (
        prefix +
        (randomInt(3) === 0 ? '0' : digits(1 + randomInt(18), true)) +
        '.' +
        digits(1 + randomInt(45))
      );

    case 2:
      return (
        prefix +
        digits(1 + randomInt(18), true) +
        (randomInt(2) === 0 ? '' : '.' + digits(1 + randomInt(60))) +
        exponent(-350, 350)
      );

    case 3:
      // Long fractional tails probe decimal rounding without constructing
      // an unbounded integer in the Elixir decoder.
      return (
        prefix +
        (randomInt(2) === 0 ? '0' : digits(1 + randomInt(8), true)) +
        '.' +
        digits(80 + randomInt(161)) +
        (randomInt(2) === 0 ? '' : exponent(-250, 250, 40))
      );

    case 4: {
      const boundaryExponents = [-324, -323, -308, -7, -6, -5, 0, 15, 20, 21, 22, 307, 308];
      const boundary = boundaryExponents[randomInt(boundaryExponents.length)];
      return (
        prefix +
        digits(1 + randomInt(17), true) +
        '.' +
        digits(1 + randomInt(35)) +
        exponent(boundary, boundary)
      );
    }

    default:
      // Exponents with long runs of leading zeroes exercise token parsing
      // independently of exponent magnitude.
      return (
        prefix +
        digits(1 + randomInt(12), true) +
        '.' +
        digits(1 + randomInt(20)) +
        exponent(-308, 308, 80)
      );
  }
}

const fixedLexemes = [
  '0',
  '0.0',
  '0e0',
  '0E+000',
  '1',
  '-1',
  '1.0',
  '-1.0',
  '1e-7',
  '-1e-7',
  '9.999999999999999e-7',
  '0.000001',
  '-0.000001',
  '9.999999999999999e20',
  '-9.999999999999999e20',
  '1e21',
  '-1e21',
  '1e+22',
  '-1e+22',
  '1.0000000000000001',
  '1.0000000000000002',
  '2.2250738585072014e-308',
  '-2.2250738585072014e-308',
  '5e-324',
  '-5e-324',
  '1.7976931348623157e308',
  '-1.7976931348623157e308',
  '9007199254740991',
  '-9007199254740991',
  '9007199254740992',
  '-9007199254740992',
  '9007199254740992.0',
  '-9007199254740992.0',
  '12345678901234567890.123456789012345678901234567890',
  '-12345678901234567890.123456789012345678901234567890',
  '0.123456789012345678901234567890123456789012345678901234567890',
  '-0.123456789012345678901234567890123456789012345678901234567890',
  '1e0000000000000000000000000000000000000000000000000021',
  '-1E+0000000000000000000000000000000000000000000000000021',
  '1e-0000000000000000000000000000000000000000000000000324',
  '1e-999',
];

function record(lexeme) {
  const value = JSON.parse(lexeme);
  if (!Number.isFinite(value)) return null;
  if (Object.is(value, -0)) return null;
  return lexeme + '\t' + JSON.stringify(value);
}

function main() {
  const count = parsePositiveCount(process.argv[2], '100000');
  const lines = [];

  while (lines.length < count) {
    const line = record(randomLexeme());
    if (line !== null) lines.push(line);
  }

  for (const lexeme of fixedLexemes) {
    const line = record(lexeme);
    if (line === null) throw new Error('invalid fixed number token: ' + lexeme);
    lines.push(line);
  }

  process.stdout.write(lines.join('\n') + '\n');
}

try {
  main();
} catch (error) {
  process.stderr.write(error.message + '\n');
  process.exitCode = 1;
}
