/**
 * paillierEngine.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Eye C You — Privacy-Preserving Biometric Authentication
 * Standalone Paillier Partially Homomorphic Encryption Engine
 *
 * Uses native JavaScript BigInt for arbitrary-precision arithmetic.
 * Implements the full Paillier cryptosystem (Pascal Paillier, 1999):
 *   - Probabilistic public-key encryption
 *   - Additive homomorphism: Enc(a) ⊗ Enc(b) = Enc(a + b) mod n²
 * ─────────────────────────────────────────────────────────────────────────────
 */

// ─── BIGINT CONSTANTS ────────────────────────────────────────────────────────
const BIGINT_ZERO = 0n;
const BIGINT_ONE = 1n;
const BIGINT_TWO = 2n;

// ─── PRIMALITY & RANDOM PRIMES ───────────────────────────────────────────────

/**
 * Miller-Rabin primality test using deterministic witnesses for numbers
 * up to 3.3 × 10²⁴.
 *
 * @param {bigint} n - Candidate prime
 * @param {number} rounds - Number of witness rounds (default 20)
 * @returns {boolean}
 */
export function millerRabinIsPrime(n, rounds = 20) {
  if (n < BIGINT_TWO) return false;
  if (n === BIGINT_TWO || n === 3n || n === 5n || n === 7n) return true;
  if (n % BIGINT_TWO === BIGINT_ZERO) return false;

  let r = BIGINT_ZERO;
  let d = n - BIGINT_ONE;
  while (d % BIGINT_TWO === BIGINT_ZERO) {
    d /= BIGINT_TWO;
    r++;
  }

  const witnesses = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

  witnessLoop: for (const a of witnesses) {
    if (a >= n) continue;
    let x = modularExponentiation(a, d, n);
    if (x === BIGINT_ONE || x === n - BIGINT_ONE) continue;
    for (let i = BIGINT_ZERO; i < r - BIGINT_ONE; i++) {
      x = modularExponentiation(x, BIGINT_TWO, n);
      if (x === n - BIGINT_ONE) continue witnessLoop;
    }
    return false;
  }
  return true;
}

/**
 * Generate a cryptographically random BigInt of exactly `bitLength` bits
 * using the Web Crypto API.
 *
 * @param {number} bitLength - Desired bit length
 * @returns {bigint}
 */
export function generateSecureRandomBigInt(bitLength) {
  const byteLength = Math.ceil(bitLength / 8);
  const randomBytes = new Uint8Array(byteLength);
  crypto.getRandomValues(randomBytes);

  randomBytes[0] |= 0x80;
  randomBytes[byteLength - 1] |= 0x01;

  let result = BIGINT_ZERO;
  for (const byte of randomBytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Generate a random BigInt in the range [2, upperBound - 1].
 *
 * @param {bigint} upperBound
 * @returns {bigint}
 */
export function generateRandomBigIntInRange(upperBound) {
  const bitLength = upperBound.toString(2).length;
  let candidate;
  do {
    candidate = generateSecureRandomBigInt(bitLength) % upperBound;
  } while (candidate < BIGINT_TWO);
  return candidate;
}

/**
 * Generate a probable prime of exactly `bitLength` bits.
 *
 * @param {number} bitLength
 * @returns {bigint}
 */
export function generateProbablePrime(bitLength) {
  let candidate;
  do {
    candidate = generateSecureRandomBigInt(bitLength);
    candidate |= BIGINT_ONE;
  } while (!millerRabinIsPrime(candidate));
  return candidate;
}

// ─── MODULAR ARITHMETIC ──────────────────────────────────────────────────────

/**
 * Fast modular exponentiation: base^exponent mod modulus
 *
 * @param {bigint} base
 * @param {bigint} exponent
 * @param {bigint} modulus
 * @returns {bigint}
 */
export function modularExponentiation(base, exponent, modulus) {
  if (modulus === BIGINT_ONE) return BIGINT_ZERO;
  let result = BIGINT_ONE;
  base = base % modulus;
  while (exponent > BIGINT_ZERO) {
    if (exponent % BIGINT_TWO === BIGINT_ONE) {
      result = (result * base) % modulus;
    }
    exponent = exponent >> BIGINT_ONE;
    base = (base * base) % modulus;
  }
  return result;
}

/**
 * Extended Euclidean Algorithm.
 * Returns { gcd, x, y } such that: a*x + b*y = gcd(a, b)
 *
 * @param {bigint} a
 * @param {bigint} b
 * @returns {{ gcd: bigint, x: bigint, y: bigint }}
 */
export function extendedGcd(a, b) {
  if (b === BIGINT_ZERO) return { gcd: a, x: BIGINT_ONE, y: BIGINT_ZERO };
  const { gcd, x: x1, y: y1 } = extendedGcd(b, a % b);
  return { gcd, x: y1, y: x1 - (a / b) * y1 };
}

/**
 * Modular multiplicative inverse of a mod modulus.
 *
 * @param {bigint} a
 * @param {bigint} modulus
 * @returns {bigint}
 */
export function modularInverse(a, modulus) {
  const { gcd, x } = extendedGcd(((a % modulus) + modulus) % modulus, modulus);
  if (gcd !== BIGINT_ONE) {
    throw new Error(`modularInverse: Value has no inverse mod ${modulus}`);
  }
  return ((x % modulus) + modulus) % modulus;
}

export function gcd(a, b) {
  while (b !== BIGINT_ZERO) {
    [a, b] = [b, a % b];
  }
  return a;
}

export function lcm(a, b) {
  return (a / gcd(a, b)) * b;
}

// ─── PAILLIER KEY GENERATION ─────────────────────────────────────────────────

/**
 * Generate a Paillier key pair.
 *
 * @param {number} primeBitLength - Bit length of each prime
 * @returns {{ publicKey: object, privateKey: object }}
 */
export function generateKeys(primeBitLength = 64) {
  let p, q, n;

  do {
    p = generateProbablePrime(primeBitLength);
    q = generateProbablePrime(primeBitLength);
  } while (p === q || gcd(p * q, (p - 1n) * (q - 1n)) !== BIGINT_ONE);

  n = p * q;
  const nSquared = n * n;
  const lambdaPrivate = lcm(p - BIGINT_ONE, q - BIGINT_ONE);
  const generatorG = n + BIGINT_ONE;
  const muPrivate = modularInverse(lambdaPrivate, n);

  return {
    publicKey: { n, nSquared, g: generatorG, bitLength: primeBitLength },
    privateKey: { lambda: lambdaPrivate, mu: muPrivate, p, q }
  };
}

// ─── ENCRYPTION & DECRYPTION ─────────────────────────────────────────────────

export function encrypt(plaintext, publicKey) {
  const { n, nSquared } = publicKey;
  const m = BigInt(plaintext);

  if (m < BIGINT_ZERO || m >= n) {
    throw new RangeError(`encrypt: plaintext must be in [0, n-1]`);
  }

  let r;
  do {
    r = generateRandomBigIntInRange(n);
  } while (gcd(r, n) !== BIGINT_ONE);

  const gExponentiated = (BIGINT_ONE + m * n) % nSquared;
  const rExponentiated = modularExponentiation(r, n, nSquared);

  return (gExponentiated * rExponentiated) % nSquared;
}

export function decrypt(ciphertext, privateKey, publicKey) {
  const { n, nSquared } = publicKey;
  const { lambda: lambdaPrivate, mu: muPrivate } = privateKey;

  const u = modularExponentiation(ciphertext, lambdaPrivate, nSquared);
  const lOfU = (u - BIGINT_ONE) / n;

  return (lOfU * muPrivate) % n;
}

// ─── HOMOMORPHIC LOGIC ───────────────────────────────────────────────────────

export function homomorphicAddition(encryptedCiphertext1, encryptedCiphertext2, publicKey) {
  return (encryptedCiphertext1 * encryptedCiphertext2) % publicKey.nSquared;
}

export function homomorphicScalarMultiply(encryptedCiphertext, scalarK, publicKey) {
  return modularExponentiation(encryptedCiphertext, BigInt(scalarK), publicKey.nSquared);
}

// ─── VECTOR OPERATIONS ───────────────────────────────────────────────────────

export function encryptIrisVector(irisVector, publicKey) {
  return irisVector.map((component) => encrypt(component, publicKey));
}

export function decryptIrisVector(encryptedIrisVector, privateKey, publicKey) {
  return encryptedIrisVector.map((ciphertext) => decrypt(ciphertext, privateKey, publicKey));
}

/**
 * Map raw modular decrypted outputs into signed BigInt spaces to process negative diffs.
 * 
 * @param {bigint} decryptedValue - Raw value output from decryption
 * @param {bigint} n - Public key modulus
 * @returns {bigint} Signed representation
 */
export function toSignedBigInt(decryptedValue, n) {
  const halfN = n / BIGINT_TWO;
  return decryptedValue > halfN ? decryptedValue - n : decryptedValue;
}

export function blindHomomorphicDifference(encryptedLiveIrisVector, encryptedStoredTemplate, publicKey) {
  if (encryptedLiveIrisVector.length !== encryptedStoredTemplate.length) {
    throw new Error("blindHomomorphicDifference: vector length mismatch");
  }

  return encryptedLiveIrisVector.map((encLive, index) => {
    const encStored = encryptedStoredTemplate[index];
    const encNegativeStored = modularInverse(encStored, publicKey.nSquared);
    return homomorphicAddition(encLive, encNegativeStored, publicKey);
  });
}

// ─── SERIALIZATION METRICS ───────────────────────────────────────────────────

export function serializeCiphertext(ciphertext) {
  return "0x" + ciphertext.toString(16);
}

export function deserializeCiphertext(hexCiphertext) {
  return BigInt(hexCiphertext);
}

export function serializeEncryptedVector(encryptedIrisVector) {
  return encryptedIrisVector.map(serializeCiphertext);
}

export function deserializeEncryptedVector(serializedEncryptedPayload) {
  return serializedEncryptedPayload.map(deserializeCiphertext);
}