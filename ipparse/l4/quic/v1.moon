--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Version 1 Module
-- This module provides constants, utilities, and metatables specific to QUIC version 1.
-- It includes definitions for packet types, header byte masks, and the initial salt used for key derivation.
-- Additionally, it provides functions to generate metatables for manipulating QUIC header fields.
--
-- ### Features
-- - Constants for QUIC version 1, including `version` and `initial_salt`.
-- - Definitions for long and short header byte masks.
-- - Bidirectional mappings for packet types and header fields.
-- - Utilities for generating metatables for QUIC header manipulation.
--
-- ### QUIC-v1 Packet Structure
-- ```
-- Long Header {
--   byte1 (8): First byte containing flags and header form.
--   version (32): QUIC version (always 0x01 for QUIC-v1).
--   dst_connection_id (variable): Destination Connection ID.
--   src_connection_id (variable): Source Connection ID.
--   payload (variable): Packet payload (e.g., frames).
-- }
--
-- Short Header {
--   byte1 (8): First byte containing flags and header form.
--   dst_connection_id (variable): Destination Connection ID.
--   payload (variable): Packet payload (e.g., frames).
-- }
-- ```
--
-- References:
-- - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
-- - RFC 9001: Using TLS to Secure QUIC
--
-- @module quic.v1

:upper = string
:bidirectional, :zero_indexed = require"ipparse.fun"

--- QUIC version number as found in the long-header version field (0x01 for version 1).
version = 0x01

--- Initial salt used for key derivation in QUIC version 1, as a hexadecimal string.
initial_salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

--- Masks for the first byte of a long QUIC header.
-- Provides bidirectional mappings for header fields such as `HEADER_FORM`, `FIXED_BIT`, and `PKT_TYPE`.
-- Lower 4 bits: Reserved (2), Packet Number Length (2)
byte1_long = bidirectional {
  HEADER_FORM:  0x80
  FIXED_BIT:    0x40
  PKT_TYPE:     0x30
  RESERVED_BITS:0x0C -- Must be 0 in v1
  PKT_NUM_LEN_BITS: 0x03  -- Encodes length-1
}

--- Masks for the first byte of a short QUIC header.
-- Provides bidirectional mappings for header fields such as `HEADER_FORM`, `FIXED_BIT`, and `KEY_PHASE`.
byte1_short = bidirectional {
  HEADER_FORM:    0x80
  FIXED_BIT:      0x40
  SPIN_BIT:       0x20
  RESERVED_BITS:  0x18
  KEY_PHASE:      0x04
  PKT_NUM_LENGTH: 0x03
}

--- Packet types for QUIC version 1.
-- Provides bidirectional mappings for packet types such as `initial`, `zero_rtt`, `handshake`, and `retry`.
raw_packet_type_names = zero_indexed {"initial", "zero_rtt", "handshake", "retry"} -- [0]="initial", [1]="0rtt", ...

-- For header manipulation (numeric values used in the byte PKT_TYPE field)
internal_header_packet_type_map = {}
for idx, raw_name in ipairs raw_packet_type_names
  val_in_header = idx << 4 -- e.g. initial (idx 0) -> 0x00, 0rtt (idx 1) -> 0x10
  internal_header_packet_type_map[raw_name] = val_in_header
  internal_header_packet_type_map[val_in_header] = raw_name
internal_header_packet_type_map = bidirectional internal_header_packet_type_map -- For lookup by name or value

packet_types_enum = { [upper raw_name]: raw_name for _, raw_name in ipairs raw_packet_type_names }

--- Generates a metatable for manipulating QUIC header fields.
-- The generated metatable allows for reading and writing header fields using string keys.
-- @tparam table byte1 A table containing bidirectional mappings for header fields.
-- @treturn table The generated metatable.
generate_mt = (byte1) -> {
  --- Reads a header field value.
  -- @tparam string k The name of the header field (e.g., `HEADER_FORM`).
  -- @treturn number The value of the header field.
  __index: (k) =>
    if type(k) == "string" then
      uk = upper k
      if uk == "TYPE" and byte1 == byte1_long -- Only long headers have explicit type field this way
        pkt_type_bits = @byte1 & byte1_long.PKT_TYPE
        return internal_header_packet_type_map[pkt_type_bits] -- Returns "initial", "handshake", etc.
      elseif uk == "PN_LENGTH" -- Actual packet number length (1-4)
        len_bits = if byte1 == byte1_long then (@byte1 & byte1_long.PKT_NUM_LEN_BITS) else (@byte1 & byte1_short.PKT_NUM_LENGTH)
        return len_bits + 1
      elseif mask = byte1[uk]
        return @byte1 & mask
    rawget @, k -- Fallback for other fields

  --- Writes a value to a header field.
  -- @tparam string k The name of the header field (e.g., `HEADER_FORM`).
  -- @tparam boolean|number v The value to set (`true` to set the field, `false` or `nil` to clear it).
  __newindex: (k, v) =>
    if type(k) == "string" then
      uk = upper k
      if uk == "TYPE" and byte1 == byte1_long
        pkt_val_for_header = nil
        if type(v) == "string" -- e.g. "initial"
          pkt_val_for_header = internal_header_packet_type_map[v] -- gets 0x00, 0x10 etc.
        elseif type(v) == "number" -- raw bits
          pkt_val_for_header = v
        if pkt_val_for_header
          @byte1 = (@byte1 & ~byte1_long.PKT_TYPE) | pkt_val_for_header
        else -- Clear if v is nil or invalid
          @byte1 = @byte1 & ~byte1_long.PKT_TYPE
      elseif uk == "PN_LENGTH"
        if type(v) == "number" and v >= 1 and v <= 4
          len_bits = v - 1
          mask_bits = if byte1 == byte1_long then byte1_long.PKT_NUM_LEN_BITS else byte1_short.PKT_NUM_LENGTH
          @byte1 = (@byte1 & ~mask_bits) | len_bits
      elseif mask = byte1[uk]
        val_to_set = v
        if v == true then val_to_set = mask
        elseif v == false then val_to_set = 0
        @byte1 = (@byte1 & ~mask) | (val_to_set or 0)
      else
        rawset @, k, v -- Allow setting other fields
    else
      rawset @, k, v
}

-- Parses the remainder of a QUIC v1 long header (after SCID)
-- Populates pkt_table with fields like token, length_field, pn_offset, payload_offset
-- fn_parse_varint is parse_variable_length_integer from frames module
parse_long_header_remainder = (pkt_table, data_str, current_off, fn_parse_varint) ->
  pkt_type_name = pkt_table.type -- Assumes .type is already resolved by __index
  next_off = current_off

  pkt_table.pn_length = (pkt_table.byte1 & byte1_long.PKT_NUM_LEN_BITS) + 1

  if pkt_type_name == "initial"
    token_len, next_off = fn_parse_varint data_str, next_off
    return next_off unless token_len -- Error or insufficient data
    pkt_table.token = if token_len > 0 then sub data_str, next_off, next_off + token_len - 1 else ""
    next_off += token_len
    length_field_val, next_off = fn_parse_varint data_str, next_off
    return next_off unless length_field_val
    pkt_table.length_field = length_field_val -- Length of PN + Encrypted Payload
  elseif pkt_type_name == "0rtt" or pkt_type_name == "handshake"
    length_field_val, next_off = fn_parse_varint data_str, next_off
    return next_off unless length_field_val
    pkt_table.length_field = length_field_val
  -- Retry packets have a different structure not covered here yet.

  pkt_table.pn_offset = next_off
  pkt_table.payload_offset = pkt_table.pn_offset + pkt_table.pn_length
  if pkt_table.length_field -- This is the "Length" field from the packet header
    pkt_table.packet_end_offset = pkt_table.pn_offset + pkt_table.length_field

  pkt_table.pn_offset -- Return the packet number offset

-- Required for parse_long_header_remainder
frames_module = require "ipparse.l4.quic.frames"

{
  :version, :initial_salt
  long_mt: generate_mt(byte1_long)
  short_mt: generate_mt(byte1_short)
  :byte1_long, :byte1_short
  packet_types_enum: packet_types_enum -- e.g. { INITIAL: "initial" }
  internal_header_packet_type_map: internal_header_packet_type_map -- e.g. { initial: 0x00, [0x00]: "initial" }
  :parse_long_header_remainder
  utils: {
    parse_variable_length_integer: frames_module.parse_variable_length_integer
  }
}
