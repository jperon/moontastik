--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Header Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating QUIC headers.
-- It supports both long and short headers, automatically determining the type and delegating to the appropriate functions.
-- Additionally, it includes utilities for handling QUIC versions, connection IDs, and flags.
--
-- ### Features
-- - Parse and pack QUIC headers (long and short).
-- - Handle QUIC versions and connection IDs.
-- - Manage QUIC-specific flags.
--
-- ### QUIC Header Structure
-- ```
-- QUIC Header {
--   byte1 (8): First byte containing flags and header form.
--   version (32): QUIC version (for long headers).
--   dst_connection_id (variable): Destination Connection ID.
--   src_connection_id (variable): Source Connection ID (for long headers).
--   payload (variable): Payload data.
-- }
-- ```
--
-- References:
-- - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
-- - RFC 8999: Version-Independent Properties of QUIC
-- - RFC 9001: Using TLS to Secure QUIC
--
-- @module quic

pack: sp, unpack: su, :byte = string
:bidirectional = require"ipparse.fun"

versions = {v.version, v for v in *[require"ipparse.l4.quic.#{v}" for v in *{"version_negotiation", "v1"}]}

-- Expose packet_type enum from v1 (or other default version)
public_packet_types = {}
if v1_module = versions[0x00000001] -- QUIC v1
  if v1_module.packet_types_enum
    public_packet_types = v1_module.packet_types_enum

-- Make parse_variable_length_integer available if provided by a version module (e.g., v1 from frames)
-- parse_variable_length_integer = versions[0x00000001]?.utils?.parse_variable_length_integer -- Original line with chained existential operator
if v1_module_for_util = versions[0x00000001]
  if v1_module_for_util.utils
    parse_variable_length_integer = v1_module_for_util.utils.parse_variable_length_integer

flags = bidirectional {
  HEADER_FORM: 0x80
}
:HEADER_FORM = flags

--- Packs the QUIC header and payload into a binary string.
-- Constructs the binary representation of the QUIC header based on whether it is a long or short header.
-- @tparam table self The QUIC header object.
-- @treturn string Binary string representing the packed QUIC header and payload.
pack = =>
  if @long_header
    sp(">BH s1 s1", @byte1, @version, @dst_connection_id, @src_connection_id)..(@data and "#{@data}" or "")
  else
    sp(">B", @byte1) .. @dst_connection_id

_mt =
  --- Converts the QUIC header object to a binary string.
  -- @tparam table self The QUIC header object.
  -- @treturn string Binary string representing the QUIC header and payload.
  __tostring: pack

for {:long_mt, :short_mt} in *versions
  long_mt[k] or= v for k, v in pairs _mt
  short_mt[k] or= v for k, v in pairs _mt

--- Parses a long QUIC header from a binary string.
-- Extracts the version, destination connection ID, and source connection ID.
-- @tparam string self The binary string containing the QUIC header.
-- @tparam number off Offset to start parsing from.
-- @tparam number byte1 The first byte of the header.
-- @treturn table Parsed QUIC header as a table.
-- @treturn number The next offset after parsing.
parse_long_header = (off, byte1) =>
  version, dcid_str, scid_str, _off_after_scid = su ">I4 s1 s1", @, off

  quic_pkt_table = {
    byte1: byte1, :version,
    dst_connection_id: dcid_str, src_connection_id: scid_str,
    long_header: true
  }

  local mt, version_module
  if v_mod = versions[version]
    version_module = v_mod
    mt = v_mod.long_mt
  mt or= _mt
  setmetatable quic_pkt_table, mt

  current_off = _off_after_scid
  if version_module and version_module.parse_long_header_remainder
    -- This function populates pn_offset, payload_offset, etc. in quic_pkt_table
    version_module.parse_long_header_remainder quic_pkt_table, @, current_off, parse_variable_length_integer
  else
    -- Fallback if no specific parser (basic handling for pn_length)
    temp_pn_len = 1
    if version_module and version_module.byte1_long and version_module.byte1_long.PKT_NUM_LEN_BITS
      temp_pn_len = (byte1 & version_module.byte1_long.PKT_NUM_LEN_BITS) + 1
    quic_pkt_table.pn_length = temp_pn_len
    quic_pkt_table.pn_offset = current_off
    quic_pkt_table.payload_offset = current_off + temp_pn_len

  quic_pkt_table, quic_pkt_table.pn_offset -- Return packet table and pn_offset

--- Parses a short QUIC header from a binary string.
-- Extracts the destination connection ID and other fields.
parse_short_header = (off, byte1, dst_id=nil, src_connection_id=nil, version=nil) =>
  local mt, parsed_dst_connection_id
  current_off = off
  if dst_id
    parsed_dst_connection_id, current_off  = su ">c#{#dst_id}", @, off

  local version_module
  if v_mod = versions[version]
    version_module = v_mod
    mt = v_mod.short_mt
  mt or= _mt

  quic_pkt_table = {
    byte1: byte1, :version,
    dst_connection_id: parsed_dst_connection_id, :src_connection_id,
    long_header: false
  }
  setmetatable quic_pkt_table, mt

  -- For short headers, Packet Number follows DCID
  pn_len = 1 -- Default
  if version_module and version_module.byte1_short and version_module.byte1_short.PKT_NUM_LENGTH
    pn_len = (byte1 & version_module.byte1_short.PKT_NUM_LENGTH) + 1
  quic_pkt_table.pn_length = pn_len
  quic_pkt_table.pn_offset = current_off
  quic_pkt_table.payload_offset = current_off + pn_len

  quic_pkt_table, quic_pkt_table.pn_offset -- Return packet table and pn_offset

--- Parses a QUIC header from a binary string.
-- Determines whether the header is long or short and delegates to the appropriate parse function.
-- @tparam string self The binary string containing the QUIC header.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @param ... Additional arguments for parsing.
-- @treturn table Parsed QUIC header as a table.
-- @treturn number The next offset after parsing.
parse = (off=1, ...) =>
  byte1 = byte @, off
  if byte1 & HEADER_FORM == 0
    parse_short_header @, off+1, byte1, ...
  else
    parse_long_header @, off+1, byte1

:versions, :pack, :parse, packet_type: public_packet_types
