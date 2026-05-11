/**
 * Minimal crypto.subtle polyfill for the Pear bare worklet runtime.
 * Sets up globalThis.crypto using @noble/hashes and @noble/ciphers so that
 * kdbxweb (which uses globalThis.crypto.subtle) works in the worklet.
 *
 * On environments where crypto.subtle already exists this is a no-op.
 */
import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512'
import { hmac } from '@noble/hashes/hmac'
import { cbc } from '@noble/ciphers/aes'
import sodium from 'sodium-native'

if (!globalThis.crypto) {
  globalThis.crypto = {}
}

if (!globalThis.crypto.getRandomValues) {
  globalThis.crypto.getRandomValues = (array) => {
    const buf = Buffer.from(array.buffer, array.byteOffset, array.byteLength)
    sodium.randombytes_buf(buf)
    return array
  }
}

if (!globalThis.crypto.subtle) {
  class PolyfillCryptoKey {
    constructor(rawKey, algorithm) {
      this.rawKey =
        rawKey instanceof Uint8Array
          ? rawKey
          : rawKey instanceof ArrayBuffer
            ? new Uint8Array(rawKey)
            : new Uint8Array(
                rawKey.buffer,
                rawKey.byteOffset,
                rawKey.byteLength
              )
      this.algorithm = algorithm
    }
  }

  const toUint8 = (data) => {
    if (data instanceof Uint8Array) return data
    if (data instanceof ArrayBuffer) return new Uint8Array(data)
    if (ArrayBuffer.isView(data))
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    throw new TypeError('Expected ArrayBuffer or TypedArray')
  }

  const toArrayBuffer = (u8) =>
    u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)

  const algName = (alg) => (typeof alg === 'string' ? alg : alg?.name || '')

  const getHashFn = (name) => {
    const n = algName(name).replace('-', '').toLowerCase()
    if (n === 'sha256') return sha256
    if (n === 'sha512') return sha512
    throw new Error(`Unsupported hash algorithm: ${name}`)
  }

  globalThis.crypto.subtle = {
    async digest(algorithm, data) {
      return toArrayBuffer(getHashFn(algorithm)(toUint8(data)))
    },

    async importKey(format, keyData, algorithm) {
      if (format !== 'raw') throw new Error(`Unsupported key format: ${format}`)
      return new PolyfillCryptoKey(keyData, algorithm)
    },

    async sign(algorithm, key, data) {
      const hashAlgName =
        key.algorithm?.hash || key.algorithm || algorithm?.hash
      return toArrayBuffer(
        hmac(getHashFn(hashAlgName), key.rawKey, toUint8(data))
      )
    },

    async encrypt(algorithm, key, data) {
      if (algName(algorithm) !== 'AES-CBC')
        throw new Error('Only AES-CBC encrypt is supported')
      return toArrayBuffer(
        cbc(key.rawKey, toUint8(algorithm.iv)).encrypt(toUint8(data))
      )
    },

    async decrypt(algorithm, key, data) {
      if (algName(algorithm) !== 'AES-CBC')
        throw new Error('Only AES-CBC decrypt is supported')
      return toArrayBuffer(
        cbc(key.rawKey, toUint8(algorithm.iv)).decrypt(toUint8(data))
      )
    }
  }
}
