--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- @module quic.crypto

-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

-- QUIC cryptographic operations

pack: sp, :sub, :byte, :char = string
:concat = table
hex2bin:ipparse_hex2bin = require"ipparse"
:tls13_expand_label = require"ipparse.l7.tls"

-- Conditionally load crypto modules

local Aead, HKDF, SKCIPHER
Aead = require"crypto.aead".new
HKDF = require"crypto.hkdf".new
SKCIPHER = require"crypto.skcipher".new


-- QUIC Initial keys derivation constants
INITIAL_SALT_V1 = ipparse_hex2bin "38762cf7f55934b34d179ae6a4c80cadccbb7f0a" -- RFC 9001

xor = (a, b) -> (a | b) & ~(a & b)

--- Derives QUIC Initial secrets using HKDF
-- @tparam string dcid Destination Connection ID
-- @treturn string client_initial_secret
-- @treturn string server_initial_secret
derive_initial_secrets = (dcid) -> -- Changed => to -> and removed leading :
  hkdf = HKDF "sha256"
  initial_secret = hkdf\extract INITIAL_SALT_V1, dcid
  client_secret = tls13_expand_label initial_secret, "client in", "", 32
  server_secret = tls13_expand_label initial_secret, "server in", "", 32
  client_secret, server_secret

--- Derives QUIC keys from secrets
-- @tparam string secret Traffic secret
-- @treturn string key Encryption key
-- @treturn string iv Initialization vector
-- @treturn string hp Header protection key
derive_keys = (secret) -> -- Changed => to -> and removed leading :
  -- Use the specific hkdf_expand_label function directly
  key = tls13_expand_label secret, "quic key", "", 16
  iv = tls13_expand_label secret, "quic iv", "", 12
  hp = tls13_expand_label secret, "quic hp", "", 16
  key, iv, hp

--- Removes header protection from QUIC packet
-- @tparam string packet The QUIC packet data
-- @tparam number pn_offset Offset of packet number in packet
-- @tparam number pn_length Length of packet number field
-- @tparam string hp_key Header protection key
-- @treturn string Packet with header protection removed
-- @treturn number Actual packet number
remove_header_protection = (packet, pn_offset, pn_length, hp_key) ->
  sample_offset = pn_offset + 4
  if #packet < sample_offset + 15
    error "Packet too short for header protection sample extraction"

  sample = sub packet, sample_offset, sample_offset + 15
  if not sample or #sample ~= 16
    error "Invalid sample extracted for header protection"

  hp_cipher = SKCIPHER "cbc(aes)"
  hp_cipher\setkey hp_key
  mask, err = hp_cipher\encrypt sample
  if not mask
    error "Failed to encrypt sample for header protection: " .. err

  first_byte = byte packet, 1

  is_long_header = (first_byte & 0x80) ~= 0
  header_protection_mask = if is_long_header then 0x0f else 0x1f

  protected_bits = first_byte & header_protection_mask
  first_byte_mask = byte mask, 1
  first_byte = (first_byte & ~header_protection_mask) | xor(protected_bits, (first_byte_mask & header_protection_mask))

  pn_bytes = {}
  for i = 1, pn_length
    pn_byte = byte packet, pn_offset + i - 1
    mask_byte = byte mask, i + 1
    pn_bytes[i] = char xor(pn_byte, mask_byte)

  packet_number = 0
  for i = 1, pn_length
    packet_number = (packet_number << 8) | byte(pn_bytes[i])

  unprotected = char(first_byte) ..
                sub(packet, 2, pn_offset - 1) ..
                concat(pn_bytes) ..
                sub(packet, pn_offset + pn_length)

  unprotected, packet_number

--- Decrypts QUIC Initial packet payload
-- @tparam string packet Unprotected packet data
-- @tparam number payload_offset Offset of encrypted payload
-- @tparam number packet_number Packet number
-- @tparam string key Encryption key
-- @tparam string iv Initialization vector
-- @treturn string Decrypted payload
decrypt_payload = (packet, payload_offset, packet_number, key, iv) ->
  pn_bytes = sp ">I8", packet_number
  nonce = {}
  iv_len = #iv
  for i = 1, iv_len
    iv_byte = byte iv, i
    pn_byte = i > iv_len - 8 and byte(pn_bytes, i - (iv_len - 8)) or 0
    nonce[i] = char xor(iv_byte, pn_byte)

  nonce_str = concat nonce
  encrypted_payload = sub packet, payload_offset
  aad = sub packet, 1, payload_offset - 1

  aead_cipher = Aead "gcm(aes)"
  aead_cipher\setkey key
  decrypted = aead_cipher\decrypt nonce_str, encrypted_payload, aad
  decrypted

-- Export the functions
{
  :derive_initial_secrets
  :derive_keys
  :remove_header_protection
  :decrypt_payload
}
