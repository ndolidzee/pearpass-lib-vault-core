/**
 * Minimal crypto.subtle polyfill for the Pear bare worklet runtime.
 * Sets up globalThis.crypto using bare-crypto's Node-style API so that
 * kdbxweb (which uses globalThis.crypto.subtle) works in the worklet.
 *
 * On environments where crypto.subtle already exists this is a no-op.
 */
import crypto from 'crypto'

const {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  randomFillSync
} = crypto

if (!globalThis.crypto) {
  globalThis.crypto = {}
}

if (!globalThis.crypto.getRandomValues) {
  globalThis.crypto.getRandomValues = (array) => {
    randomFillSync(array)
    return array
  }
}

if (!globalThis.crypto.subtle) {
  class PolyfillCryptoKey {
    constructor(rawKey, algorithm) {
      this.rawKey = Buffer.isBuffer(rawKey)
        ? rawKey
        : Buffer.from(
            rawKey instanceof ArrayBuffer
              ? rawKey
              : new Uint8Array(
                  rawKey.buffer,
                  rawKey.byteOffset,
                  rawKey.byteLength
                )
          )
      this.algorithm = algorithm
    }
  }

  const toBuffer = (data) => {
    if (Buffer.isBuffer(data)) return data
    if (data instanceof ArrayBuffer) return Buffer.from(data)
    if (ArrayBuffer.isView(data))
      return Buffer.from(data.buffer, data.byteOffset, data.byteLength)
    throw new TypeError('Expected ArrayBuffer or TypedArray')
  }

  const toArrayBuffer = (buf) =>
    buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)

  const algName = (alg) => (typeof alg === 'string' ? alg : alg?.name || '')

  const getHashName = (name) => name.replace('-', '').toLowerCase()

  const getAesCipherAlgorithm = (keyLen) => {
    if (keyLen === 16) return 'aes-128-cbc'
    if (keyLen === 32) return 'aes-256-cbc'
    throw new Error(`Unsupported AES key length: ${keyLen}`)
  }

  globalThis.crypto.subtle = {
    async digest(algorithm, data) {
      const hashName = getHashName(algName(algorithm))
      const result = createHash(hashName).update(toBuffer(data)).digest()
      return toArrayBuffer(result)
    },

    async importKey(format, keyData, algorithm) {
      if (format !== 'raw') throw new Error(`Unsupported key format: ${format}`)
      return new PolyfillCryptoKey(keyData, algorithm)
    },

    async sign(algorithm, key, data) {
      const hashAlgName =
        key.algorithm?.hash || key.algorithm || algorithm?.hash
      const hashName = getHashName(algName(hashAlgName))
      const mac = createHmac(hashName, key.rawKey)
        .update(toBuffer(data))
        .digest()
      return toArrayBuffer(mac)
    },

    async encrypt(algorithm, key, data) {
      if (algName(algorithm) !== 'AES-CBC')
        throw new Error('Only AES-CBC encrypt is supported')
      const iv = toBuffer(algorithm.iv)
      const cipherAlg = getAesCipherAlgorithm(key.rawKey.byteLength)
      const cipher = createCipheriv(cipherAlg, key.rawKey, iv)
      const result = Buffer.concat([
        cipher.update(toBuffer(data)),
        cipher.final()
      ])
      return toArrayBuffer(result)
    },

    async decrypt(algorithm, key, data) {
      if (algName(algorithm) !== 'AES-CBC')
        throw new Error('Only AES-CBC decrypt is supported')
      const iv = toBuffer(algorithm.iv)
      const cipherAlg = getAesCipherAlgorithm(key.rawKey.byteLength)
      const decipher = createDecipheriv(cipherAlg, key.rawKey, iv)
      const result = Buffer.concat([
        decipher.update(toBuffer(data)),
        decipher.final()
      ])
      return toArrayBuffer(result)
    }
  }
}
