--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- A module for symmetric key ciphers using OpenSSL.
-- This module provides an interface to perform encryption and decryption operations
-- using various symmetric key algorithms supported by OpenSSL.
-- @module skcipher
:open, :popen = io
:tmpname = os
:rep = string
:rm = require"sh"
:bin2hex = require"util"

read = => if @
  ret = @read"*a"
  @close! and ret

fread = => read open @

--- skcipher class
-- Represents a symmetric key cipher that can be used for encryption and decryption.
-- @type skcipher
-- @field cipher_name The name of the cipher (e.g., "cbc(aes)").
-- @field key The encryption key.
-- @field ossl_cipher The OpenSSL cipher string derived from the cipher name and key.
skcipher = {}

--- Creates a new skcipher object.
-- @tparam string cipher_name The name of the cipher (e.g., "cbc(aes)").
-- @treturn skcipher A new skcipher instance.
skcipher.new = (cipher_name) ->
  @ = {}
  @cipher_name = cipher_name
  @key = nil
  @ossl_cipher = nil
  setmetatable @, {__index: skcipher}
  @

--- Sets the encryption key for the skcipher instance.
-- Validates the key length for AES-CBC ciphers.
-- @tparam string key The encryption key.
-- @raise error If the key length is invalid for AES-CBC.
skcipher.setkey = (key) =>
  mode, algo = @cipher_name\match "^(%w+)%((%w+)%)"
  key_len = #key * 8
  if algo == "aes" and mode == "cbc" and key_len ~= 128 and key_len ~= 192 and key_len ~= 256
    error "Invalid key length for AES-CBC"
  @ossl_cipher = algo\upper! .. "-" .. key_len .. "-" .. mode\upper!
  @key = key

operation = (op = "e") -> (iv, data) =>
  if not data
    data = iv
    iv = rep "\0", 12 -- 12-byte zero-filled IV for header protection

  tmp = tmpname!
  command = "openssl enc -nopad -#{@ossl_cipher} -#{op} -K #{bin2hex @key} -iv #{bin2hex iv} >" .. tmp
  if p = popen command, "w"
    p\write data
    p\close!
    fread(tmp), rm(tmp)
  else
    nil, "popen failed"

--- Encrypts data using the configured cipher and key.
-- @tparam string iv The initialization vector.
-- @tparam string data The data to encrypt.
-- @treturn string The encrypted data.
skcipher.encrypt = operation "e"

--- Decrypts data using the configured cipher and key.
-- @tparam string iv The initialization vector.
-- @tparam string data The data to decrypt.
-- @treturn string The decrypted data.
skcipher.decrypt = operation "d"

skcipher
