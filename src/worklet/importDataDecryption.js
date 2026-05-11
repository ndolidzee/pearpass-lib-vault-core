// import './utils/setupWorkletCrypto.js'
// import { argon2id, argon2d } from '@noble/hashes/argon2'
// import * as _kdbxweb from 'kdbxweb'
import crypto from 'bare-crypto'

// import { decryptExportData } from './exportDataEncryption'

// const kdbxweb = _kdbxweb.default || _kdbxweb

// // ---------------------------------------------------------------------------
// // KeePass (kdbxweb) setup
// // ---------------------------------------------------------------------------

// kdbxweb.CryptoEngine.setArgon2Impl(
//   (password, salt, memory, iterations, length, parallelism, type) => {
//     const hashFn =
//       type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d
//     return hashFn(new Uint8Array(password), new Uint8Array(salt), {
//       t: iterations,
//       m: memory,
//       p: parallelism,
//       dkLen: length
//     })
//   }
// )

// /**
//  * Decrypts a KDBX (KeePass 2.x) binary file and returns it as a KeePass XML
//  * string, which lib-import's parseKeePassXml can process directly.
//  * @param {ArrayBuffer} arrayBuffer
//  * @param {string} password
//  * @returns {Promise<string>} KeePass XML string
//  */
// const decryptKeePassKdbx = async (arrayBuffer, password) => {
//   let db
//   try {
//     const credentials = new kdbxweb.Credentials(
//       kdbxweb.ProtectedValue.fromString(password)
//     )
//     db = await kdbxweb.Kdbx.load(
//       new Uint8Array(arrayBuffer).buffer,
//       credentials
//     )
//   } catch (error) {
//     if (
//       error?.code === kdbxweb.Consts.ErrorCodes.InvalidKey ||
//       error?.message?.includes('InvalidKey') ||
//       error?.message?.includes('Invalid key') ||
//       error?.message?.includes('invalid key') ||
//       error?.code === 'InvalidKey'
//     ) {
//       throw new Error('Incorrect password')
//     }
//     throw new Error(`Failed to open database: ${error.message || error}`)
//   }

//   return db.saveXml()
// }

// // ---------------------------------------------------------------------------
// // Bitwarden decryption helpers using bare-crypto
// // ---------------------------------------------------------------------------

// // HKDF-Expand for a single 32-byte block (RFC 5869, SHA-256 PRF)
// const hkdfExpand32 = (prk, info) => {
//   const infoBytes = Buffer.from(info, 'utf8')
//   const data = Buffer.alloc(infoBytes.length + 1)
//   infoBytes.copy(data)
//   data[infoBytes.length] = 1
//   return crypto.createHmac('sha256', prk).update(data).digest()
// }

// const timingSafeEqual = (a, b) => {
//   if (a.length !== b.length) return false
//   let diff = 0
//   for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
//   return diff === 0
// }

// const parseBitwardenCipherString = (cipherString) => {
//   const dot = cipherString.indexOf('.')
//   const type = parseInt(cipherString.slice(0, dot), 10)
//   if (type !== 2) throw new Error(`Unsupported CipherString type: ${type}`)
//   const parts = cipherString.slice(dot + 1).split('|')
//   if (parts.length !== 3) throw new Error('Invalid CipherString format')
//   return {
//     iv: Buffer.from(parts[0], 'base64'),
//     ct: Buffer.from(parts[1], 'base64'),
//     mac: Buffer.from(parts[2], 'base64')
//   }
// }

// const aesCbcDecrypt = (cipherString, encKey, macKey) => {
//   const { iv, ct, mac } = parseBitwardenCipherString(cipherString)

//   const combined = Buffer.concat([iv, ct])
//   const expectedMac = crypto
//     .createHmac('sha256', macKey)
//     .update(combined)
//     .digest()
//   if (!timingSafeEqual(expectedMac, mac)) throw new Error('Incorrect password')

//   const decipher = crypto.createDecipheriv('aes-256-cbc', encKey, iv)
//   const decrypted = Buffer.concat([decipher.update(ct), decipher.final()])
//   return decrypted.toString('utf8')
// }

// /**
//  * Decrypts a Bitwarden password-protected encrypted JSON export.
//  * Supports both PBKDF2-SHA256 (kdfType 0) and Argon2id (kdfType 1).
//  * @param {string} encryptedText - Raw file content
//  * @param {string} password
//  * @returns {Promise<object>} Decrypted vault JSON
//  */
// const decryptBitwardenVault = async (encryptedText, password) => {
//   const json = JSON.parse(encryptedText)

//   if (!json.encrypted || !json.passwordProtected) {
//     throw new Error('File is not password-protected')
//   }

//   // Bitwarden encodes the salt as raw UTF-8 bytes, NOT base64
//   const salt = Buffer.from(json.salt, 'utf8')
//   const passwordBuf = Buffer.from(password, 'utf8')
//   const kdfType = json.kdfType ?? 0

//   let masterKey
//   if (kdfType === 0) {
//     masterKey = crypto.pbkdf2Sync(
//       passwordBuf,
//       salt,
//       json.kdfIterations,
//       32,
//       'sha256'
//     )
//   } else if (kdfType === 1) {
//     // Argon2id: Bitwarden pre-hashes the salt with SHA-256
//     const saltHashed = crypto.createHash('sha256').update(salt).digest()
//     masterKey = argon2id(passwordBuf, saltHashed, {
//       t: json.kdfIterations,
//       m: (json.kdfMemory ?? 64) * 1024,
//       p: json.kdfParallelism ?? 4,
//       dkLen: 32
//     })
//   } else {
//     throw new Error(`Unsupported KDF type: ${kdfType}`)
//   }

//   const encKey = hkdfExpand32(masterKey, 'enc')
//   const macKey = hkdfExpand32(masterKey, 'mac')

//   const decryptedText = aesCbcDecrypt(json.data, encKey, macKey)
//   return JSON.parse(decryptedText)
// }

// // ---------------------------------------------------------------------------
// // Unified entry point
// // ---------------------------------------------------------------------------

// /**
//  * Decrypts an encrypted import file.
//  *
//  * Supported formats:
//  * - 'keepass'   — KDBX file (data must be base64-encoded binary)
//  * - 'bitwarden' — Bitwarden encrypted JSON export (data is a JSON string)
//  * - 'pearpass'  — PearPass encrypted JSON export (data is a JSON string)
//  *
//  * @param {string} data      - Base64-encoded binary for keepass; JSON string for others
//  * @param {string} password
//  * @param {string} format    - 'keepass' | 'bitwarden' | 'pearpass'
//  * @returns {Promise<object|Array>}
//  */
export const decryptImportData = async (data, password, format) => {
  switch (format) {
    case 'keepass': {
      const buf = Buffer.from(data, 'base64')
      const arrayBuffer = buf.buffer.slice(
        buf.byteOffset,
        buf.byteOffset + buf.byteLength
      )
      console.log('Decrypting KeePass file with size', arrayBuffer.byteLength)
      return
    }
    case 'bitwarden': {
      console.log('Decrypting Bitwarden vault with size', data.length)
      // return decryptBitwardenVault(data, password)
    }
    case 'pearpass': {
      const encryptedData = typeof data === 'string' ? JSON.parse(data) : data
      console.log('Decrypting PearPass export with size')
      // return decryptExportData(encryptedData, password)
    }
    default:
      throw new Error(`Unknown import format: ${format}`)
  }
}
