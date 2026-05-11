// import './utils/setupWorkletCrypto.js'
import { argon2id, argon2d } from 'hash-wasm'
import * as _kdbxweb from 'kdbxweb'

import crypto from 'bare-crypto'
import { decryptExportData } from './exportDataEncryption'

const { createHash, createHmac, createDecipheriv, pbkdf2Sync } = crypto

const kdbxweb = _kdbxweb.default || _kdbxweb

// ---------------------------------------------------------------------------
// KeePass (kdbxweb) setup
// ---------------------------------------------------------------------------

kdbxweb.CryptoEngine.setArgon2Impl(
  (password, salt, memory, iterations, length, parallelism, type) => {
    const hashFn =
      type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d
    return hashFn({
      password: new Uint8Array(password),
      salt: new Uint8Array(salt),
      memorySize: memory,
      iterations,
      hashLength: length,
      parallelism,
      outputType: 'binary'
    })
  }
)

/**
 * Decrypts a KDBX (KeePass 2.x) binary file and returns it as a KeePass XML
 * string, which lib-import's parseKeePassXml can process directly.
 * @param {ArrayBuffer} arrayBuffer
 * @param {string} password
 * @returns {Promise<string>} KeePass XML string
 */
const decryptKeePassKdbx = async (arrayBuffer, password) => {
  let db
  try {
    const credentials = new kdbxweb.Credentials(
      kdbxweb.ProtectedValue.fromString(password)
    )
    db = await kdbxweb.Kdbx.load(
      new Uint8Array(arrayBuffer).buffer,
      credentials
    )
  } catch (error) {
    if (
      error?.code === kdbxweb.Consts.ErrorCodes.InvalidKey ||
      error?.message?.includes('InvalidKey') ||
      error?.message?.includes('Invalid key') ||
      error?.message?.includes('invalid key') ||
      error?.code === 'InvalidKey'
    ) {
      throw new Error('Incorrect password')
    }
    throw new Error(`Failed to open database: ${error.message || error}`)
  }

  return db.saveXml()
}

// ---------------------------------------------------------------------------
// Bitwarden decryption helpers using bare-crypto
// ---------------------------------------------------------------------------

// HKDF-Expand for a single 32-byte block (RFC 5869, SHA-256 PRF)
const hkdfExpand32 = (prk, info) => {
  const prkBuf = Buffer.isBuffer(prk) ? prk : Buffer.from(new Uint8Array(prk))
  return createHmac('sha256', prkBuf)
    .update(Buffer.concat([Buffer.from(info, 'utf8'), Buffer.from([1])]))
    .digest()
}

const timingSafeEqual = (a, b) => {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

const parseBitwardenCipherString = (cipherString) => {
  const dot = cipherString.indexOf('.')
  const type = parseInt(cipherString.slice(0, dot), 10)
  if (type !== 2) throw new Error(`Unsupported CipherString type: ${type}`)
  const parts = cipherString.slice(dot + 1).split('|')
  if (parts.length !== 3) throw new Error('Invalid CipherString format')
  return {
    iv: Buffer.from(parts[0], 'base64'),
    ct: Buffer.from(parts[1], 'base64'),
    mac: Buffer.from(parts[2], 'base64')
  }
}

const aesCbcDecrypt = (cipherString, encKey, macKey) => {
  const { iv, ct, mac } = parseBitwardenCipherString(cipherString)

  const expectedMac = createHmac('sha256', macKey)
    .update(Buffer.concat([iv, ct]))
    .digest()
  if (!timingSafeEqual(expectedMac, mac)) throw new Error('Incorrect password')

  const decipher = createDecipheriv('aes-256-cbc', encKey, iv)
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8')
}

/**
 * Decrypts a Bitwarden password-protected encrypted JSON export.
 * Supports both PBKDF2-SHA256 (kdfType 0) and Argon2id (kdfType 1).
 * @param {string} encryptedText - Raw file content
 * @param {string} password
 * @returns {Promise<object>} Decrypted vault JSON
 */
const decryptBitwardenVault = async (encryptedText, password) => {
  const json = JSON.parse(encryptedText)

  if (!json.encrypted || !json.passwordProtected) {
    throw new Error('File is not password-protected')
  }

  // Bitwarden encodes the salt as raw UTF-8 bytes, NOT base64
  const salt = Buffer.from(json.salt, 'utf8')
  const passwordBuf = Buffer.from(password, 'utf8')
  const kdfType = json.kdfType ?? 0

  let masterKey
  if (kdfType === 0) {
    masterKey = pbkdf2Sync(passwordBuf, salt, json.kdfIterations, 32, 'sha256')
  } else if (kdfType === 1) {
    // Argon2id: Bitwarden pre-hashes the salt with SHA-256
    const saltHashed = createHash('sha256').update(salt).digest()
    masterKey = await argon2id({
      password: new Uint8Array(passwordBuf),
      salt: new Uint8Array(saltHashed),
      parallelism: json.kdfParallelism ?? 4,
      iterations: json.kdfIterations,
      memorySize: (json.kdfMemory ?? 64) * 1024,
      hashLength: 32,
      outputType: 'binary'
    })
  } else {
    throw new Error(`Unsupported KDF type: ${kdfType}`)
  }

  const encKey = hkdfExpand32(masterKey, 'enc')
  const macKey = hkdfExpand32(masterKey, 'mac')

  const decryptedText = aesCbcDecrypt(json.data, encKey, macKey)
  return JSON.parse(decryptedText)
}

// ---------------------------------------------------------------------------
// Unified entry point
// ---------------------------------------------------------------------------

/**
 * Decrypts an encrypted import file.
 *
 * Supported formats:
 * - 'keepass'   — KDBX file (data must be base64-encoded binary)
 * - 'bitwarden' — Bitwarden encrypted JSON export (data is a JSON string)
 * - 'pearpass'  — PearPass encrypted JSON export (data is a JSON string)
 *
 * @param {string} data      - Base64-encoded binary for keepass; JSON string for others
 * @param {string} password
 * @param {string} format    - 'keepass' | 'bitwarden' | 'pearpass'
 * @returns {Promise<object|Array>}
 */
export const decryptImportData = async (data, password, format) => {
  switch (format) {
    case 'keepass': {
      const buf = Buffer.from(data, 'base64')
      const arrayBuffer = buf.buffer.slice(
        buf.byteOffset,
        buf.byteOffset + buf.byteLength
      )
      return decryptKeePassKdbx(arrayBuffer, password)
    }
    case 'bitwarden': {
      return decryptBitwardenVault(data, password)
    }
    case 'pearpass': {
      const encryptedData = typeof data === 'string' ? JSON.parse(data) : data
      return decryptExportData(encryptedData, password)
    }
    default:
      throw new Error(`Unknown import format: ${format}`)
  }
}
