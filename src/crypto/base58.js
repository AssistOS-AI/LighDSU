"use strict";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = 58;
const ALPHABET_MAP = new Map();
for (let i = 0; i < ALPHABET.length; i += 1) {
  ALPHABET_MAP.set(ALPHABET[i], i);
}

function encode(input) {
  const source = Buffer.from(input);
  if (source.length === 0) return "";
  let zeros = 0;
  while (zeros < source.length && source[zeros] === 0) zeros += 1;

  const digits = [0];
  for (let i = zeros; i < source.length; i += 1) {
    let carry = source[i];
    for (let j = 0; j < digits.length; j += 1) {
      const x = digits[j] * 256 + carry;
      digits[j] = x % BASE;
      carry = (x / BASE) | 0;
    }
    while (carry > 0) {
      digits.push(carry % BASE);
      carry = (carry / BASE) | 0;
    }
  }

  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    out += ALPHABET[digits[i]];
  }
  return out;
}

function decode(value) {
  if (typeof value !== "string") {
    throw new TypeError("Base58 input must be string");
  }
  if (value.length === 0) return Buffer.alloc(0);

  let zeros = 0;
  while (zeros < value.length && value[zeros] === "1") zeros += 1;

  const bytes = [0];
  for (let i = zeros; i < value.length; i += 1) {
    const char = value[i];
    const n = ALPHABET_MAP.get(char);
    if (n === undefined) {
      throw new TypeError(`Invalid base58 char: ${char}`);
    }
    let carry = n;
    for (let j = 0; j < bytes.length; j += 1) {
      const x = bytes[j] * BASE + carry;
      bytes[j] = x & 0xff;
      carry = x >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = Buffer.alloc(zeros + bytes.length);
  out.fill(0, 0, zeros);
  for (let i = 0; i < bytes.length; i += 1) {
    out[out.length - 1 - i] = bytes[i];
  }
  return out;
}

module.exports = { encode, decode };
