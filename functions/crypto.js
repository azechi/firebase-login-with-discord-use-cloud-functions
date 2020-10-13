const crypto = require("crypto");
const compare = require("tsscmp");

const qs = require("qs");

module.exports = { randomString, Hmac };

function randomString(byteSize) {
  return toBase64Url(crypto.randomBytes(byteSize));
}

function Hmac(algorithm, key) {
  /**
   * Hmac sha256 digest base64url
   * @param {string | Buffer | TypedArray | DataView} data
   * @return {string} - Base64url encoded string
   */
  this.sign = function (data) {
    const digest = crypto
      .createHmac(algorithm, key)
      .update(data) // string | Buffer | TypedArray | DataView
      .digest();
    return toBase64Url(digest);
  };

  this.verify = function (sign, value) {
    return compare(sign, this.sign(value));
  };
}

/**
 * Encode a Buffer to Base64Url
 * @param {Buffer} buffer
 * @return {string} Base64Url encoded string
 */
function toBase64Url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\/|\+|=/g, (x) => ({ "/": "_", "+": "-", "=": "" }[x]));
}
