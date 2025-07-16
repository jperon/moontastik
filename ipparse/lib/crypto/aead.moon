--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- A module for Authenticated Encryption with Associated Data (AEAD) using OpenSSL.
-- This module provides an interface to perform AEAD encryption and decryption operations
-- using various algorithms supported by OpenSSL.
-- @module aead
core_cipher = require"openssl".cipher
sub = string.sub
concat = table.concat

-- Helper to parse algo strings like "gcm(aes)" or "ecb(aes)"
-- Returns { mode: "gcm", base_algo: "aes" } or nil
parse_cipher_algo_str = (algo_str) ->
  mode, base_algo = algo_str\match"^(%w+)%((%w+)%)"
  mode and {:mode, :base_algo}

-- Helper to map base_algo and key length to openssl cipher type
-- e.g., "aes" with 16-byte key, mode "gcm" -> "AES-128-GCM"
get_openssl_cipher_type = (base_algo, mode, key_len_bytes) ->
  if base_algo == "aes"
    bits = key_len_bytes * 8
    -- For AEAD, lua-openssl typically expects "AES-<bits>-<MODE>" (e.g., "AES-128-GCM")
    return "AES-#{bits}-#{mode\upper!}"
  error "Unsupported base algorithm for cipher type: #{base_algo}"

--- aead class
-- Represents an AEAD cipher that can be used for encryption and decryption.
-- @type aead
-- @field cipher_name The name of the cipher (e.g., "gcm(aes)").
-- @field key The encryption key.
-- @field ossl_cipher The OpenSSL cipher string derived from the cipher name and key.
-- @field tag_len_bytes The length of the authentication tag in bytes.
aead = {}

--- Creates a new aead object.
-- @tparam string cipher_name The name of the cipher (e.g., "gcm(aes)").
-- @treturn aead A new aead instance.
aead.new = (cipher_name) ->
  @ = {}
  @cipher_name = cipher_name
  parsed_algo = parse_cipher_algo_str cipher_name
  if not parsed_algo
    error "Invalid AEAD algorithm string: #{cipher_name}. Expected format like 'gcm(aes)'."
  if parsed_algo.mode\lower! ~= "gcm"
    error "Unsupported AEAD algorithm mode: #{parsed_algo.mode}. Only GCM is supported by this wrapper."

  @_key = nil
  @_openssl_type = nil
  @_base_algo = parsed_algo.base_algo\lower!
  @_mode = parsed_algo.mode\lower!
  @tag_len_bytes = 16 -- Common for AES-GCM, can be overridden by setauthsize
  setmetatable @, {__index: aead}
  @

--- Sets the encryption key for the aead instance.
-- Validates the key length for AES-GCM ciphers.
-- @tparam string key The encryption key.
-- @raise error If the key length is invalid for AES-GCM.
aead.setkey = (key) =>
  @_key = key
  @_openssl_type = get_openssl_cipher_type @_base_algo, @_mode, #@_key
  unless @_openssl_type
    error "Cannot determine OpenSSL cipher type for #{@_base_algo} with key length #{#@_key} in AEAD setkey"

--- Sets the authentication tag size for the AEAD instance.
-- @tparam number size The tag size in bytes.
aead.setauthsize = (size) =>
  @tag_len_bytes = size

--- Returns the authentication tag size for the AEAD instance.
-- @treturn number The tag size in bytes.
aead.authsize = => @tag_len_bytes

--- Encrypts data using the configured cipher and key.
-- @tparam string iv The initialization vector.
-- @tparam string data The data to encrypt.
-- @tparam string aad Optional associated authenticated data.
-- @treturn string The encrypted data with authentication tag appended.
aead.encrypt = (nonce_iv, plaintext, aad) =>
  unless @_key and @_openssl_type
    error "AEAD key not set or type not determined. Call setkey() first."

  ctx = core_cipher.get(@_openssl_type)\encrypt_new() -- Initialize without IV
  assert(ctx\ctrl(core_cipher.EVP_CTRL_GCM_SET_IVLEN, #nonce_iv)) -- Set IV length
  assert(ctx\init(@_key, nonce_iv)) -- Initialize with key and IV
  ctx\padding(false) -- Disable padding for AEAD

  if aad and #aad > 0
    ctx\update(aad, true) -- Set the AAD if provided

  parts = {}
  update_res = ctx\update(plaintext) -- Encrypt the plaintext
  if update_res and #update_res > 0
    parts[#parts+1] = update_res

  final_res = ctx\final() -- Final block
  if final_res and #final_res > 0
    parts[#parts+1] = final_res

  tag = assert(ctx\ctrl(core_cipher.EVP_CTRL_GCM_GET_TAG, @tag_len_bytes)) -- Get the authentication tag
  parts[#parts+1] = tag

  return concat(parts)

--- Decrypts data using the configured cipher and key.
-- @tparam string iv The initialization vector.
-- @tparam string data The data to decrypt (including authentication tag).
-- @tparam string aad Optional associated authenticated data.
-- @treturn string The decrypted data.
-- @treturn nil If decryption/authentication fails, returns nil.
-- @treturn string An error message if decryption/authentication fails.
aead.decrypt = (nonce_iv, ciphertext_with_tag, aad) =>
  unless @_key and @_openssl_type
    error "AEAD key not set or type not determined. Call setkey() first."

  actual_ciphertext_len = #ciphertext_with_tag - @tag_len_bytes
  if actual_ciphertext_len < 0
    return nil, "Ciphertext too short to contain tag"

  actual_ciphertext = sub(ciphertext_with_tag, 1, actual_ciphertext_len)
  tag_from_payload = sub(ciphertext_with_tag, actual_ciphertext_len + 1)

  ctx = core_cipher.get(@_openssl_type)\decrypt_new() -- Initialize without IV
  assert(ctx\ctrl(core_cipher.EVP_CTRL_GCM_SET_IVLEN, #nonce_iv)) -- Set IV length
  assert(ctx\init(@_key, nonce_iv)) -- Initialize with key and IV
  ctx\padding(false)

  if aad and #aad > 0
    ctx\update(aad, true) -- Set the AAD if provided

  parts = {}
  update_res = ctx\update(actual_ciphertext) -- Decrypt the ciphertext
  if update_res and #update_res > 0
    parts[#parts+1] = update_res

  assert(ctx\ctrl(core_cipher.EVP_CTRL_GCM_SET_TAG, tag_from_payload)) -- Set the authentication tag

  ok, final_res_or_err = pcall -> ctx\final() -- Finalize decryption and check for errors

  if ok
    if type(final_res_or_err) == "string" and #final_res_or_err > 0
      parts[#parts+1] = final_res_or_err
    elseif final_res_or_err == false -- Explicit false means failure
      return nil, "AEAD decryption failed (tag mismatch or other error)"
    -- If final_res_or_err is true, it means success and no final block data
    return concat(parts)
  else
    return nil, "AEAD decryption failed: " .. tostring(final_res_or_err)

aead
