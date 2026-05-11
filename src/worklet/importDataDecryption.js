import crypto from 'bare-crypto'
import { argon2id } from '@noble/hashes/argon2'
import { decryptExportData } from './exportDataEncryption'

// ---------------------------------------------------------------------------
// Bitwarden decryption helpers
// ---------------------------------------------------------------------------

// HKDF-Expand for a single 32-byte block (RFC 5869, SHA-256 PRF)
const hkdfExpand32 = (prk, info) => {
  const infoBytes = Buffer.from(info, 'utf8')
  const data = Buffer.alloc(infoBytes.length + 1)
  infoBytes.copy(data)
  data[infoBytes.length] = 1
  return crypto.createHmac('sha256', prk).update(data).digest()
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

  const combined = Buffer.concat([iv, ct])
  const expectedMac = crypto.createHmac('sha256', macKey).update(combined).digest()
  if (!timingSafeEqual(expectedMac, mac)) throw new Error('Incorrect password')

  const decipher = crypto.createDecipheriv('aes-256-cbc', encKey, iv)
  const decrypted = Buffer.concat([decipher.update(ct), decipher.final()])
  return decrypted.toString('utf8')
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
    masterKey = crypto.pbkdf2Sync(passwordBuf, salt, json.kdfIterations, 32, 'sha256')
  } else if (kdfType === 1) {
    // Argon2id: Bitwarden pre-hashes the salt with SHA-256
    const saltHashed = crypto.createHash('sha256').update(salt).digest()
    masterKey = argon2id(new Uint8Array(passwordBuf), saltHashed, {
      t: json.kdfIterations,
      m: (json.kdfMemory ?? 64) * 1024,
      p: json.kdfParallelism ?? 4,
      dkLen: 32
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
 * - 'bitwarden' — Bitwarden encrypted JSON export (data is a JSON string)
 * - 'pearpass'  — PearPass encrypted JSON export (data is a JSON string)
 *
 * @param {string} data      - JSON string
 * @param {string} password
 * @param {string} format    - 'bitwarden' | 'pearpass'
 * @returns {Promise<object>}
 */
export const decryptImportData = async (data, password, format) => {
  switch (format) {
    case 'bitwarden':
      return decryptBitwardenVault(data, password)
    case 'pearpass': {
      const encryptedData = typeof data === 'string' ? JSON.parse(data) : data
      return decryptExportData(encryptedData, password)
    }
    default:
      throw new Error(`Unknown import format: ${format}`)
  }
}
