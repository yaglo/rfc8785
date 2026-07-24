// Deterministic generator for the es6testfile100m number corpus of
// cyberphone/json-canonicalization.
//
// Derived from and modified from upstream testdata/numgen.js:
// Copyright 2006-2021 WebPKI.org (http://webpki.org).
// Licensed under the Apache License, Version 2.0.
//
// Modifications Copyright 2026 Stanislav Yaglo.
//
// The value sequence (static table, serial smallest normals,
// SHA-256-chained randoms) is reproduced so that the stream can be
// verified against the published prefix checksums without downloading
// the 4 GB corpus file.
//
// Usage: node es6_corpus.js <lines>
//
// stdout: one "hex-ieee,expected" line per value, plus metadata lines
//   "#checkpoint <lines> <ok|mismatch> <sha256>" at each published
//   checkpoint crossed.
'use strict';
const crypto = require("crypto")

// Typed-array reinterpretation uses the host's byte order. Use DataView with
// an explicit order instead so this generator reproduces the published
// little-endian SHA-chain algorithm on every architecture.
const scratch = new DataView(new ArrayBuffer(8))
function bitsToFloat(bits) {
	scratch.setBigUint64(0, bits, false)
	return scratch.getFloat64(0, false)
}
function floatToBits(value) {
	scratch.setFloat64(0, value, false)
	return scratch.getBigUint64(0, false)
}

const staticU64s = new BigUint64Array([
	0x0000000000000000n, 0x8000000000000000n, 0x0000000000000001n, 0x8000000000000001n,
	0xc46696695dbd1cc3n, 0xc43211ede4974a35n, 0xc3fce97ca0f21056n, 0xc3c7213080c1a6acn,
	0xc39280f39a348556n, 0xc35d9b1f5d20d557n, 0xc327af4c4a80aaacn, 0xc2f2f2a36ecd5556n,
	0xc2be51057e155558n, 0xc28840d131aaaaacn, 0xc253670dc1555557n, 0xc21f0b4935555557n,
	0xc1e8d5d42aaaaaacn, 0xc1b3de4355555556n, 0xc17fca0555555556n, 0xc1496e6aaaaaaaabn,
	0xc114585555555555n, 0xc0e046aaaaaaaaabn, 0xc0aa0aaaaaaaaaaan, 0xc074d55555555555n,
	0xc040aaaaaaaaaaabn, 0xc00aaaaaaaaaaaabn, 0xbfd5555555555555n, 0xbfa1111111111111n,
	0xbf6b4e81b4e81b4fn, 0xbf35d867c3ece2a5n, 0xbf0179ec9cbd821en, 0xbecbf647612f3696n,
	0xbe965e9f80f29212n, 0xbe61e54c672874dbn, 0xbe2ca213d840baf8n, 0xbdf6e80fe033c8c6n,
	0xbdc2533fe68fd3d2n, 0xbd8d51ffd74c861cn, 0xbd5774ccac3d3817n, 0xbd22c3d6f030f9acn,
	0xbcee0624b3818f79n, 0xbcb804ea293472c7n, 0xbc833721ba905bd3n, 0xbc4ebe9c5db3c61en,
	0xbc18987d17c304e5n, 0xbbe3ad30dfcf371dn, 0xbbaf7b816618582fn, 0xbb792f9ab81379bfn,
	0xbb442615600f9499n, 0xbb101e77800c76e1n, 0xbad9ca58cce0be35n, 0xbaa4a1e0a3e6fe90n,
	0xba708180831f320dn, 0xba3a68cd9e985016n, 0x446696695dbd1cc3n, 0x443211ede4974a35n,
	0x43fce97ca0f21056n, 0x43c7213080c1a6acn, 0x439280f39a348556n, 0x435d9b1f5d20d557n,
	0x4327af4c4a80aaacn, 0x42f2f2a36ecd5556n, 0x42be51057e155558n, 0x428840d131aaaaacn,
	0x4253670dc1555557n, 0x421f0b4935555557n, 0x41e8d5d42aaaaaacn, 0x41b3de4355555556n,
	0x417fca0555555556n, 0x41496e6aaaaaaaabn, 0x4114585555555555n, 0x40e046aaaaaaaaabn,
	0x40aa0aaaaaaaaaaan, 0x4074d55555555555n, 0x4040aaaaaaaaaaabn, 0x400aaaaaaaaaaaabn,
	0x3fd5555555555555n, 0x3fa1111111111111n, 0x3f6b4e81b4e81b4fn, 0x3f35d867c3ece2a5n,
	0x3f0179ec9cbd821en, 0x3ecbf647612f3696n, 0x3e965e9f80f29212n, 0x3e61e54c672874dbn,
	0x3e2ca213d840baf8n, 0x3df6e80fe033c8c6n, 0x3dc2533fe68fd3d2n, 0x3d8d51ffd74c861cn,
	0x3d5774ccac3d3817n, 0x3d22c3d6f030f9acn, 0x3cee0624b3818f79n, 0x3cb804ea293472c7n,
	0x3c833721ba905bd3n, 0x3c4ebe9c5db3c61en, 0x3c18987d17c304e5n, 0x3be3ad30dfcf371dn,
	0x3baf7b816618582fn, 0x3b792f9ab81379bfn, 0x3b442615600f9499n, 0x3b101e77800c76e1n,
	0x3ad9ca58cce0be35n, 0x3aa4a1e0a3e6fe90n, 0x3a708180831f320dn, 0x3a3a68cd9e985016n,
	0x4024000000000000n, 0x4014000000000000n, 0x3fe0000000000000n, 0x3fa999999999999an,
	0x3f747ae147ae147bn, 0x3f40624dd2f1a9fcn, 0x3f0a36e2eb1c432dn, 0x3ed4f8b588e368f1n,
	0x3ea0c6f7a0b5ed8dn, 0x3e6ad7f29abcaf48n, 0x3e35798ee2308c3an, 0x3ed539223589fa95n,
	0x3ed4ff26cd5a7781n, 0x3ed4f95a762283ffn, 0x3ed4f8c60703520cn, 0x3ed4f8b72f19cd0dn,
	0x3ed4f8b5b31c0c8dn, 0x3ed4f8b58d1c461an, 0x3ed4f8b5894f7f0en, 0x3ed4f8b588ee37f3n,
	0x3ed4f8b588e47da4n, 0x3ed4f8b588e3849cn, 0x3ed4f8b588e36bb5n, 0x3ed4f8b588e36937n,
	0x3ed4f8b588e368f8n, 0x3ed4f8b588e368f1n, 0x3ff0000000000000n, 0xbff0000000000000n,
	0xbfeffffffffffffan, 0xbfeffffffffffffbn, 0x3feffffffffffffan, 0x3feffffffffffffbn,
	0x3feffffffffffffcn, 0x3feffffffffffffen, 0xbfefffffffffffffn, 0xbfefffffffffffffn,
	0x3fefffffffffffffn, 0x3fefffffffffffffn, 0x3fd3333333333332n, 0x3fd3333333333333n,
	0x3fd3333333333334n, 0x0010000000000000n, 0x000ffffffffffffdn, 0x000fffffffffffffn,
	0x7fefffffffffffffn, 0xffefffffffffffffn, 0x4340000000000000n, 0xc340000000000000n,
	0x4430000000000000n, 0x44b52d02c7e14af5n, 0x44b52d02c7e14af6n, 0x44b52d02c7e14af7n,
	0x444b1ae4d6e2ef4en, 0x444b1ae4d6e2ef4fn, 0x444b1ae4d6e2ef50n, 0x3eb0c6f7a0b5ed8cn,
	0x3eb0c6f7a0b5ed8dn, 0x41b3de4355555553n, 0x41b3de4355555554n, 0x41b3de4355555555n,
	0x41b3de4355555556n, 0x41b3de4355555557n, 0xbecbf647612f3696n, 0x43143ff3c1cb0959n,
])
const staticF64s = Array.from(staticU64s, bitsToFloat)
const serialU64s = new BigUint64Array(2000)
for (let i = 0; i < 2000; i++) {
	serialU64s[i] = 0x0010000000000000n + BigInt(i)
}
const serialF64s = Array.from(serialU64s, bitsToFloat)

const state = {
    idx: 0,
    data: [],
    block: Buffer.alloc(32),
}
function next() {
    let f = 0.0;
    if (state.idx < staticF64s.length) {
        f = staticF64s[state.idx]
    } else if (state.idx < staticF64s.length + serialF64s.length) {
        f = serialF64s[state.idx - staticF64s.length]
    } else {
        while (f == 0.0 || !isFinite(f)) {
            if (state.data.length == 0) {
                state.block = crypto.createHash("sha256").update(state.block).digest()
                const view = new DataView(
                    state.block.buffer,
                    state.block.byteOffset,
                    state.block.byteLength
                )
                state.data = Array.from({length: 4}, (_, i) => view.getFloat64(i * 8, true))
            }
            f = state.data[0]
            state.data = state.data.slice(1)
        }
    }
    state.idx++
    return f
}

function parseCorpusCount(raw, fallback) {
  const text = raw === undefined ? fallback : raw
  if (!/^[0-9]+$/.test(text)) {
    throw new Error('line count must be a decimal integer from 1000 to 100000000')
  }

  const count = Number(text)
  if (!Number.isSafeInteger(count) || count < 1000 || count > 100000000) {
    throw new Error('line count must be a decimal integer from 1000 to 100000000')
  }
  return count
}

const N = parseCorpusCount(process.argv[2], '100000')
const CHECKPOINTS = {
  1000: 'be18b62b6f69cdab33a7e0dae0d9cfa869fda80ddc712221570f9f40a5878687',
  10000: 'b9f7a8e75ef22a835685a52ccba7f7d6bdc99e34b010992cbc5864cd12be6892',
  100000: '22776e6d4b49fa294a0d0f349268e5c28808fe7e0cb2bcbe28f63894e494d4c7',
  1000000: '49415fee2c56c77864931bd3624faad425c3c577d6d74e89a83bc725506dad16',
  10000000: 'b9f8a44a91d46813b21b9602e72f112613c91408db0b8341fb94603d9db135e0',
  100000000: '0f7dda6b0837dde083c5d6b896f7d62340c8a2415b0c7121d83145e08a755272',
}

const hash = crypto.createHash('sha256')

async function main() {
  let pending = []
  let pendingBytes = 0
  for (let i = 1; i <= N; i++) {
    const value = next()
    const line = floatToBits(value).toString(16) + ',' + value.toString() + '\n'
    hash.update(line)
    pending.push(line)
    pendingBytes += line.length
    if (CHECKPOINTS[i]) {
      const got = hash.copy().digest('hex')
      const status = got === CHECKPOINTS[i] ? 'ok' : 'mismatch'
      pending.push('#checkpoint ' + i + ' ' + status + ' ' + got + '\n')
    }
    if (pendingBytes >= 1 << 20 || i === N) {
      const chunk = pending.join('')
      pending = []
      pendingBytes = 0
      if (!process.stdout.write(chunk)) {
        await new Promise(resolve => process.stdout.once('drain', resolve))
      }
    }
  }
}

main()
