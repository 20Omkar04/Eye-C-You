/**
 * supabaseClient.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Eye C You — Supabase Cloud Gateway Integration Layer
 *
 * Handles all communication between the client machine and the
 * privacy-preserving Supabase cloud backend. The backend NEVER
 * receives plaintext biometric data — only ciphertext string arrays.
 *
 * Database schema (SQL):
 * ─────────────────────────────────────────────────────────────────────────────
 * CREATE TABLE eye_c_you_biometric_templates (
 *   id                          uuid DEFAULT gen_random_uuid() PRIMARY KEY,
 *   subject_identifier          text NOT NULL UNIQUE,
 *   encrypted_iris_payload      text[] NOT NULL,   -- hex-encoded ciphertext array
 *   paillier_n_public_modulus   text NOT NULL,     -- n serialized as hex string
 *   key_bit_length              integer NOT NULL,
 *   registration_timestamp      timestamptz DEFAULT now(),
 *   last_auth_attempt_timestamp timestamptz,
 *   auth_attempt_count          integer DEFAULT 0
 * );
 *
 * -- Enable Row Level Security
 * ALTER TABLE eye_c_you_biometric_templates ENABLE ROW LEVEL SECURITY;
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { createClient } from "@supabase/supabase-js";
import {
  deserializeEncryptedVector,
} from "../logic/paillierEngine";

// ─── CLIENT INITIALIZATION ───────────────────────────────────────────────────

const SUPABASE_PROJECT_URL =
  import.meta.env.VITE_SUPABASE_URL || "https://your-project-ref.supabase.co";

const SUPABASE_ANON_PUBLIC_KEY =
  import.meta.env.VITE_SUPABASE_ANON_KEY || "your-supabase-anon-key";

const BIOMETRIC_TEMPLATES_TABLE = "eye_c_you_biometric_templates";

export const supabaseCloudGatewayClient = createClient(
  SUPABASE_PROJECT_URL,
  SUPABASE_ANON_PUBLIC_KEY
);

// ─── REGISTRATION / UPSERT ───────────────────────────────────────────────────

/**
 * Register or update a subject's encrypted iris template in Supabase.
 *
 * @param {Object} registrationPayload
 * @returns {Promise<{ data: any, error: object|null }>}
 */
export async function upsertEncryptedIrisTemplate(registrationPayload) {
  const {
    subjectIdentifier,
    encryptedIrisPayload,
    paillierNPublicModulus,
    keyBitLength,
  } = registrationPayload;

  // Validate that the payload contains only serialized ciphertext strings
  const allElementsAreCiphertextStrings = encryptedIrisPayload.every(
    (element) => typeof element === "string" && element.startsWith("0x")
  );

  if (!allElementsAreCiphertextStrings) {
    throw new TypeError(
      "upsertEncryptedIrisTemplate: encryptedIrisPayload must contain hex-encoded ciphertext strings only. " +
      "Raw biometric values must never be transmitted to the cloud gateway."
    );
  }

  const cloudDatabaseRecord = {
    subject_identifier: subjectIdentifier,
    encrypted_iris_payload: encryptedIrisPayload,       // string[] of hex ciphertexts
    paillier_n_public_modulus: paillierNPublicModulus,   // public modulus as hex string
    key_bit_length: keyBitLength,
    registration_timestamp: new Date().toISOString(),
  };

  const { data, error } = await supabaseCloudGatewayClient
    .from(BIOMETRIC_TEMPLATES_TABLE)
    .upsert(cloudDatabaseRecord, {
      onConflict: "subject_identifier",
    })
    .select();

  if (error) {
    console.error("[SupabaseGateway] Upsert failed:", error.message);
  } else {
    console.log(
      `[SupabaseGateway] ✅ Encrypted template stored for subject: ${subjectIdentifier}`
    );
  }

  return { data, error };
}

// ─── FETCH STORED TEMPLATE ───────────────────────────────────────────────────

/**
 * Retrieve the stored encrypted iris template for a given subject.
 *
 * @param {string} subjectIdentifier
 * @returns {Promise<{ encryptedStoredIrisVector: bigint[]|null, cloudRecord: any|null, error: any }>}
 */
export async function fetchEncryptedIrisTemplate(subjectIdentifier) {
  const { data: cloudRecord, error } = await supabaseCloudGatewayClient
    .from(BIOMETRIC_TEMPLATES_TABLE)
    .select("*")
    .eq("subject_identifier", subjectIdentifier)
    .maybeSingle(); // Prevents throwing an unhandled exception if no rows exist

  if (error || !cloudRecord) {
    console.warn(
      `[SupabaseGateway] No template found for subject: ${subjectIdentifier}`
    );
    return { encryptedStoredIrisVector: null, cloudRecord: null, error };
  }

  // Deserialize hex ciphertext strings → BigInt array for homomorphic ops
  const encryptedStoredIrisVector = deserializeEncryptedVector(
    cloudRecord.encrypted_iris_payload
  );

  console.log(
    `[SupabaseGateway] 🔐 Retrieved ${encryptedStoredIrisVector.length}-component ` +
    `encrypted template for: ${subjectIdentifier}`
  );

  return { encryptedStoredIrisVector, cloudRecord, error: null };
}

// ─── BLIND CLOUD VERIFICATION ────────────────────────────────────────────────

/**
 * Execute a blind homomorphic authentication verification on the cloud.
 *
 * @param {any[]} encryptedLiveIrisVector   - Fresh encrypted scan from client (BigInt or Hex String)
 * @param {any[]} encryptedStoredTemplate   - Template retrieved from DB (BigInt or Hex String)
 * @param {object} publicKey                 - Public key object
 * @returns {Promise<{ encryptedDifferenceVector: bigint[], cloudComputeLog: string[] }>}
 */
export async function executeBlindCloudVerification(
  encryptedLiveIrisVector,
  encryptedStoredTemplate,
  publicKey
) {
  const cloudComputeLog = [];
  const { nSquared } = publicKey;

  cloudComputeLog.push(
    `[CLOUD] Received ${encryptedLiveIrisVector.length} encrypted iris components`
  );
  cloudComputeLog.push(
    `[CLOUD] Public modulus n² bit-length: ${nSquared.toString(2).length} bits`
  );
  cloudComputeLog.push("[CLOUD] Initiating zero-knowledge homomorphic computation...");

  const encryptedDifferenceVector = [];

  for (let componentIndex = 0; componentIndex < encryptedLiveIrisVector.length; componentIndex++) {
    // Defensive sanitization: Explicitly cast to BigInt in case inputs are hex strings
    const encLive = BigInt(encryptedLiveIrisVector[componentIndex]);
    const encStored = BigInt(encryptedStoredTemplate[componentIndex]);

    // Blind inverse: Enc(-b) = Enc(n - b) = modular inverse of Enc(b) in Z_{n²}
    const encNegativeStored = modInverseBigInt(encStored, nSquared);

    // Homomorphic subtraction: Enc(live - stored) = Enc(live) · Enc(-stored) mod n²
    const encDifference = (encLive * encNegativeStored) % nSquared;
    encryptedDifferenceVector.push(encDifference);

    cloudComputeLog.push(
      `[CLOUD] Component[${componentIndex}]: HE-SUB complete → ` +
      `${encDifference.toString(16).slice(0, 24)}...`
    );
  }

  cloudComputeLog.push("[CLOUD] ✅ Blind computation complete. Returning Enc(Δ) to client.");
  cloudComputeLog.push("[CLOUD] Zero plaintext exposure achieved — privacy preserved.");

  return { encryptedDifferenceVector, cloudComputeLog };
}

/**
 * Update the authentication attempt timestamp and atomics for audit logging.
 *
 * Requires a Database RPC function to safely run atomic additions:
 * CREATE OR REPLACE FUNCTION increment_auth_attempts(target_subject text)
 * RETURNS void AS $$
 * BEGIN
 *   UPDATE eye_c_you_biometric_templates
 *   SET auth_attempt_count = auth_attempt_count + 1,
 *       last_auth_attempt_timestamp = now()
 *   WHERE subject_identifier = target_subject;
 * END;
 * $$ LANGUAGE plpgsql;
 *
 * @param {string} subjectIdentifier
 * @returns {Promise<void>}
 */
export async function logAuthenticationAttempt(subjectIdentifier) {
  // Execute via an explicit server-side remote procedure call
  const { error } = await supabaseCloudGatewayClient.rpc("increment_auth_attempts", {
    target_subject: subjectIdentifier,
  });

  if (error) {
    console.error("[SupabaseGateway] Failed to update metric logs:", error.message);
  }
}

// ─── INTERNAL HELPERS ─────────────────────────────────────────────────────────

/**
 * Modular multiplicative inverse for BigInt.
 *
 * @param {bigint} a
 * @param {bigint} m
 * @returns {bigint}
 */
function modInverseBigInt(a, m) {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  return ((old_s % m) + m) % m;
}