--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- @module quic.sni

-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

-- QUIC SNI extraction functionality

unpack: su, :sub, :byte = string
parse: ClientHello = require "l7.tls.handshake.client_hello"
parse: ServerName = require "l7.tls.handshake.extension.server_name"
:derive_initial_secrets, :derive_keys, :remove_header_protection, :decrypt_payload = require "l4.quic.crypto"
:parse_variable_length_integer = require "l4.quic.frames"
:parse_long_header_remainder = require "l4.quic.v1"
reassembler = require "ipparse.lib.reassembler"
:iter_frames = require "l4.quic.frames"

QUIC_VERSION_1 = 0x00000001

--- Parses QUIC Initial packet header
-- @tparam string data Packet data
-- @tparam number off Offset to parse from
-- @treturn table|nil Parsed header information
-- @treturn number|nil Offset of packet number field
-- @treturn string|nil Error message
-- @raise Error if data is not a string or offset is invalid
parse_initial_header = (data, off=1) =>
  assert type(data) == "string", "Invalid data: must be string"
  assert type(off) == "number" and off >= 1, "Invalid offset"

  return nil, nil, "Data too short for header parsing" if #data < off

  first_byte = byte data, off
  return nil, nil, "Failed to read first byte" unless first_byte

  header_form = (first_byte & 0x80) >> 7
  packet_type = (first_byte & 0x30) >> 4

  return nil, nil, "Not an Initial packet" if header_form ~= 1 or packet_type ~= 0

  off = off + 1

  return nil, nil, "Data too short for version field" if #data < off + 4

  version, next_off = su ">I4", data, off
  return nil, nil, "Failed to parse version" unless version

  return nil, nil, "Unsupported QUIC version" if version ~= QUIC_VERSION_1

  off = next_off

  -- Parse DCID
  return nil, nil, "Data too short for DCID length" if #data < off + 1

  dcid_len = byte data, off
  return nil, nil, "Failed to read DCID length" unless dcid_len

  off = off + 1
  return nil, nil, "Data too short for DCID" if #data < off + dcid_len

  dcid = sub data, off, off + dcid_len - 1
  off = off + dcid_len

  -- Parse SCID
  return nil, nil, "Data too short for SCID length" if #data < off + 1

  scid_len = byte data, off
  return nil, nil, "Failed to read SCID length" unless scid_len

  off = off + 1
  return nil, nil, "Data too short for SCID" if #data < off + scid_len

  scid = sub data, off, off + scid_len - 1
  off = off + scid_len

  -- Create a dummy packet table to pass to parse_long_header_remainder
  pkt_table = {
    byte1: first_byte
    version: version
    dcid: dcid
    scid: scid
    long_header: true
  }

  pn_offset = parse_long_header_remainder pkt_table, data, off, parse_variable_length_integer
  return nil, nil, "Failed to parse long header remainder" unless pn_offset

  -- Populate remaining fields from pkt_table
  pkt_table.packet_type = packet_type
  pkt_table.header_form = header_form
  pkt_table.data_off = pkt_table.pn_offset -- This is the start of the packet number
  pkt_table.payload_off = pkt_table.pn_offset + pkt_table.pn_length -- This is the start of the encrypted payload

  pkt_table, pn_offset

--- Parses CRYPTO frame from decrypted payload
-- @tparam string payload Decrypted payload data
-- @tparam number off Offset to parse from
-- @treturn string|nil CRYPTO frame data
-- @treturn number|nil Next offset
-- @treturn string|nil Error message
-- @raise Error if payload is not a string or offset is invalid
parse_crypto_frame = (payload, off=1) =>
  assert type(payload) == "string", "Invalid payload: must be string"
  assert type(off) == "number" and off >= 1, "Invalid offset"

  return nil, nil, "Payload too short for frame parsing" if #payload < off

  frame_type = byte payload, off
  return nil, nil, "Failed to read frame type" unless frame_type

  return nil, nil, "Not a CRYPTO frame" if frame_type ~= 0x06

  off = off + 1

  -- Parse offset
  _, next_off, err = parse_variable_length_integer payload, off
  return nil, nil, err or "Failed to parse frame offset" unless next_off

  off = next_off

  -- Parse length
  crypto_len, next_off, err = parse_variable_length_integer payload, off
  return nil, nil, err or "Failed to parse frame length" unless crypto_len

  off = off + 1
  return nil, nil, "Payload too short for frame data" if #payload < off + crypto_len - 1

  crypto_data = sub payload, off, off + crypto_len - 1
  crypto_data, off + crypto_len

--- Extracts SNI from TLS ClientHello in CRYPTO frame
-- @tparam string crypto_data TLS handshake data
-- @treturn string|nil Error message
-- @raise Error if crypto_data is not a string
:extract_sni_from_crypto = (crypto_data) =>
  assert type(crypto_data) == "string", "Invalid crypto_data: must be string"

  ch = ClientHello crypto_data
  return nil, "Failed to parse ClientHello" unless ch and ch.version and ch.extensions

  for ext in *ch.extensions
    return nil, "Invalid extension data" if #ext < 4

    ext_type = su ">H", ext, 1
    return nil, "Failed to parse extension type" unless ext_type

    if ext_type == 0x0000 -- Server Name extension
      ext_data = sub ext, 5
      return nil, "Failed to extract extension data" unless ext_data

      sn = ServerName ext_data
      return sn.name if sn and sn.name

  return nil, "No SNI found in ClientHello"

--- Main SNI extraction function for QUIC Initial packets
-- @tparam string packet_data Complete UDP payload containing QUIC packet
-- @treturn string|nil SNI hostname if successfully extracted
-- @treturn string|nil Error message if extraction failed
-- @raise Error if packet_data is not a string
:extract_sni = (packet_data) =>
  assert type(packet_data) == "string", "Invalid packet_data: must be string"

  header, pn_offset, err = parse_initial_header packet_data
  return nil, err or "Failed to parse QUIC header" unless header

  client_secret, err = derive_initial_secrets header.dcid
  return nil, err or "Failed to derive initial secrets" unless client_secret

  client_key, client_iv, client_hp, err = derive_keys client_secret
  return nil, err or "Failed to derive keys" unless client_key

  unprotected_packet, packet_number, err = remove_header_protection(
    packet_data, pn_offset, header.pn_length, client_hp
  )
  return nil, err or "Failed to remove header protection" unless unprotected_packet

  payload_offset = pn_offset + header.pn_length

  decrypted_payload = decrypt_payload(
    unprotected_packet, payload_offset, packet_number, client_key, client_iv
  )
  return nil, "Failed to decrypt payload" unless decrypted_payload

  -- Collect and reassemble CRYPTO frames
  crypto_reassembler = reassembler!
  reassembled_crypto_data = nil

  for frame in iter_frames decrypted_payload
    if frame.type == "CRYPTO"
      print "DEBUG: Calling reassembler with data_len=#{#frame.data}, offset=#{frame.offset}, last=false"
      reassembled_crypto_data = crypto_reassembler frame.data, frame.offset, false -- Not necessarily last frame
    else
      -- For SNI, we only care about CRYPTO frames. Other frames are ignored.
      -- In a full parser, these would be handled or skipped based on their type/length.
      nil

  -- Mark the last frame for reassembler
  if reassembled_crypto_data then
    print "DEBUG: Calling reassembler with data_len=0, offset=0, last=true (end of stream)"
    reassembled_crypto_data = crypto_reassembler "", 0, true -- Signal end of stream

  return nil, "No reassembled CRYPTO data found" unless reassembled_crypto_data

  sni, err = extract_sni_from_crypto reassembled_crypto_data
  return nil, err or "No SNI found" unless sni

  sni, "SNI extracted successfully"

:extract_sni, :parse_initial_header, :parse_crypto_frame
