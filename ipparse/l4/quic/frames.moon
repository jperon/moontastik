--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Frame Parsing Module
-- This module provides utilities for parsing QUIC frames from a plaintext QUIC packet payload.
--
-- @module quic.frames

pack: sp, unpack: su, :byte, :sub = string

-- QUIC Frame Types (RFC 9000, Section 12.4)
-- Only implementing CRYPTO for SNI purposes here.
CRYPTO_FRAME_TYPE = 0x06
-- Other frame types: PADDING (0x00), PING (0x01), ACK (0x02-0x03), etc.

--- Parses a QUIC variable-length integer (RFC 9000, Section 16).
-- @tparam string data The binary string.
-- @tparam number off The offset to start parsing from.
-- @treturn number value The parsed integer value.
-- @treturn number next_offset The offset after the parsed integer.
-- @treturn nil, string err_msg If parsing fails.
parse_variable_length_integer = (data, off) ->
  b1 = byte data, off
  if not b1 then return nil, nil, "Insufficient data for varint first byte"

  len_indicator = b1 >> 6
  val = b1 & 0x3F

  if len_indicator == 0 -- 1-byte
    return val, off + 1
  elseif len_indicator == 1 -- 2-byte
    if off + 1 > #data then return nil, nil, "Insufficient data for 2-byte varint"
    val = (val << 8) + byte(data, off + 1)
    return val, off + 2
  elseif len_indicator == 2 -- 4-byte
    if off + 3 > #data then return nil, nil, "Insufficient data for 4-byte varint"
    val = (val << 24) + (byte(data, off + 1) << 16) + (byte(data, off + 2) << 8) + byte(data, off + 3)
    return val, off + 4
  else -- 8-byte (len_indicator == 3)
    -- Lua 5.1/5.2 numbers might not handle full 62-bit range accurately.
    -- For SNI, frame types, offsets, lengths are unlikely to exceed 30-bit range.
    if off + 7 > #data then return nil, nil, "Insufficient data for 8-byte varint"
    val = val * (2^56) -- Shifting by more than 31-32 bits is problematic with standard Lua numbers
    for i = 1, 7
      val += byte(data, off + i) * (2^((7-i)*8))
    return val, off + 8

--- Parses a single QUIC frame.
-- @tparam string data The plaintext payload data.
-- @tparam number off Offset to start parsing from.
-- @treturn table frame The parsed frame object, or nil if end of data/error.
-- @treturn number next_offset The offset after the parsed frame.
parse_frame = (data, off) ->
  frame_type, off = parse_variable_length_integer data, off
  if not frame_type then return nil, off -- End of data or error in varint

  if frame_type == CRYPTO_FRAME_TYPE -- Only one CRYPTO frame type: 0x06
    offset_val, off = parse_variable_length_integer data, off
    length_val, off = parse_variable_length_integer data, off
    if not length_val or off + length_val > #data + 1 then return nil, #data + 1, "Invalid CRYPTO frame length"
    crypto_data = sub data, off, off + length_val - 1
    return {type: "CRYPTO", offset: offset_val, len: length_val, data: crypto_data}, off + length_val
  else
    print "DEBUG: Skipping unknown/unhandled frame type: #{string.format("0x%x", frame_type)} at offset #{off}"
    -- Attempt to parse a variable-length integer as the length, if present.
    -- This is a common pattern for many QUIC frames.
    frame_len, next_off_after_len, err = parse_variable_length_integer data, off
    if frame_len and next_off_after_len and (next_off_after_len + frame_len - 1 <= #data)
      -- Successfully parsed a length, skip the frame data
      return {type: "UNKNOWN", type_val: frame_type}, next_off_after_len + frame_len
    else
      -- If no length field or parsing failed, just skip a minimal number of bytes
      -- This is a fallback for frames without explicit length or if parsing fails.
      return {type: "UNKNOWN", type_val: frame_type}, off + 1 -- Consume 1 byte for the type, then continue

--- Iterates over QUIC frames in a plaintext payload.
-- @tparam string data The plaintext payload.
-- @treturn function Iterator function returning each parsed frame.
iter_frames = (data) ->
  current_offset = 1
  max_offset = #data
  ->
    if current_offset <= max_offset
      frame, next_off, err = parse_frame data, current_offset
      if frame
        current_offset = next_off
        return frame
      else -- parse_frame indicated error or end
        current_offset = max_offset + 1 -- stop iteration
        return nil --, err
    nil

{
  :CRYPTO_FRAME_TYPE
  :parse_variable_length_integer
  :parse_frame
  :iter_frames
}
