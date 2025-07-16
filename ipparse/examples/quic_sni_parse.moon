#!/usr/bin/env moon

-- ipparse - Learn How to Parse QUIC SNI from Reassembled Frames
-- =============================================================
--
-- This tutorial demonstrates how to use the `ipparse` library to reassemble
-- consecutive QUIC frames, decrypt the payload, and extract the Server Name Indication (SNI)
-- from a TLS ClientHello message embedded within a QUIC Initial packet.
--
-- Prerequisites:
-- - `ipparse` library compiled and available in your LUA_PATH.

-- Setup: Require necessary modules
ethernet  = require "ipparse.l2.ethernet"
ip        = require "ipparse.l3.ip"
udp       = require "ipparse.l4.udp"
quic      = require "ipparse.l4.quic.init"
quic_v1   = require "ipparse.l4.quic.v1"
quic_frames = require "ipparse.l4.quic.frames"
ok, quic_crypto = pcall require, "ipparse.l4.quic.crypto"
reassembler = require "ipparse.lib.reassembler"
tls       = require "ipparse.l7.tls.init"
handshake = require "ipparse.l7.tls.handshake.init"
hello     = require "ipparse.l7.tls.handshake.client_hello"
sni       = require "ipparse.l7.tls.handshake.extension.server_name"
ipp       = require "ipparse"

unless ok
  print "Error: Failed to load 'ipparse.l4.quic.crypto'. Ensure it's available and Lunatik crypto is working."
  print "Details: #{quic_crypto}" -- quic_crypto here is the error message
  return

arg = arg  -- localize `arg` for better readability
assert arg[1], "Usage: quic_sni_parse.moon <frames_file>"

-- Read all content from the file once
file_content = nil
file_handle = io.open arg[1], "r"
if file_handle
  file_content = file_handle\read "*a"
  file_handle\close!
else
  print "Error: Could not open file #{arg[1]}"
  return

assert file_content, "Failed to read file content from #{arg[1]}"

-- Parse hex strings from file content
frames_hex_strings = [frame for frame in file_content\gmatch "[^,]+"]
frames = [ipp.hex2bin(s\gsub "%s", "") for s in *frames_hex_strings]

print "--- Parsing QUIC SNI from Raw Packet ---"

udp_dgrams = {}
for i, frame in ipairs frames
  print "\n--- Parsing Frame #{i} ---"

  -- Step 1: Parse Layer 2 - Ethernet Frame
  eth_frame, l3_offset = ethernet.parse frame

  unless eth_frame
    print "Error: Failed to parse Ethernet frame #{i}."
    return

  print "\n-- Layer 2: Ethernet (Frame #{i}) --"
  print "Destination MAC: #{ethernet.mac2s eth_frame.dst}"
  print "Source MAC: #{ethernet.mac2s eth_frame.src}"
  print "EtherType: 0x#{string.format "%04x", eth_frame.protocol} (#{ethernet.proto[eth_frame.protocol] or "Unknown"})"

  assert eth_frame.protocol == ethernet.proto.IP4 or eth_frame.protocol == ethernet.proto.IP6, "Expected IPv4 or IPv6 packet for Frame #{i}"

  -- Step 2: Parse Layer 3 - IP Packet
  ip_packet, l4_offset = ip.parse frame, l3_offset, eth_frame.protocol

  unless ip_packet
    print "Error: Failed to parse IP packet #{i}."
    return

  print "\n-- Layer 3: IP (Frame #{i}) --"
  print "Version: #{ip_packet.version}"
  print "Source IP: #{ip.ip2s ip_packet.src}"
  print "Destination IP: #{ip.ip2s ip_packet.dst}"
  print "Protocol: 0x#{string.format "%02x", ip_packet.protocol} (#{ip.proto[ip_packet.protocol] or "Unknown"})"

  assert ip_packet.protocol == ip.proto.UDP, "Expected UDP packet for QUIC in Frame #{i}"

  -- Step 3: Parse Layer 4 - UDP Datagram
  udp_dgram, l7_offset = udp.parse frame, l4_offset

  unless udp_dgram
    print "Error: Failed to parse UDP datagram #{i}."
    return

  print "\n-- Layer 4: UDP (Frame #{i}) --"
  print "Source Port: #{udp_dgram.spt}"
  print "Destination Port: #{udp_dgram.dpt}"
  print "Length: #{udp_dgram.len}"

  assert udp_dgram.dpt == 443 or udp_dgram.spt == 443, "Expected UDP port 443 for QUIC in Frame #{i}"

  table.insert udp_dgrams, {frame, l7_offset}

crypto_frames_data = {}
quic_pkts = {}

for i, udp_dgram in ipairs udp_dgrams
  print "\n--- Processing QUIC Packet in UDP Datagram #{i} ---"

  -- Step 4a: Parse QUIC Header
  -- quic.parse returns: packet_table, pn_offset
  -- pn_offset is also available as quic_pkt.pn_offset
  -- payload_offset is available as quic_pkt.payload_offset
  quic_pkt, _ = quic.parse udp_dgram[1], udp_dgram[2]

  unless quic_pkt
    print "Error: Failed to parse QUIC packet from UDP datagram #{i}."
    return

  print "QUIC Packet Type: #{quic_pkt.type}" -- quic_pkt.type should be a string like "initial"
  print "QUIC Version: 0x#{string.format "%x", quic_pkt.version}"
  print "Destination Connection ID: #{ipp.bin2hex quic_pkt.dst_connection_id}"
  print "Source Connection ID: #{ipp.bin2hex quic_pkt.src_connection_id}"

  assert quic_pkt.type == quic.packet_type.INITIAL, "Expected Initial packet for SNI extraction"

  -- Step 4b: Derive Initial Secrets and Keys
  client_secret, server_secret = quic_crypto.derive_initial_secrets quic_pkt.dst_connection_id
  client_key, client_iv, client_hp = quic_crypto.derive_keys client_secret

  -- Step 4c: Remove Header Protection
  unprotected_packet, packet_number = quic_crypto.remove_header_protection(
    udp_dgram[1], quic_pkt.pn_offset, quic_pkt.pn_length, client_hp
  )

  unless unprotected_packet
    print "Error: Failed to remove header protection for packet #{i}."
    return

  print "Packet Number: #{packet_number}"

  -- Step 4d: Decrypt Payload
  decrypted_payload = quic_crypto.decrypt_payload(
    unprotected_packet, quic_pkt.payload_offset, packet_number, client_key, client_iv
  )

  unless decrypted_payload
    print "Error: Failed to decrypt payload for packet #{i}."
    return

  print "Decrypted Payload Length: #{#decrypted_payload}"

  -- Step 4e: Iterate through QUIC Frames and extract CRYPTO frames
  for frame in quic_frames.iter_frames decrypted_payload
    if frame.type == "CRYPTO"
      print "Found CRYPTO frame in packet #{i}: Offset #{frame.offset}, Length #{frame.len}"
      table.insert crypto_frames_data, {offset: frame.offset, data: frame.data}
    else
      print "Skipping non-CRYPTO frame type: #{frame.type} in packet #{i}"

  table.insert quic_pkts, quic_pkt

-- Step 5: Reassemble CRYPTO Frames
print "\n-- Reassembling CRYPTO Frames --"
crypto_reassembler = reassembler!
reassembled_crypto_data = nil
for i, cf in ipairs crypto_frames_data
  reassembled_crypto_data = crypto_reassembler cf.data, cf.offset, i == #crypto_frames_data

unless reassembled_crypto_data
  print "Error: Failed to reassemble CRYPTO data."
  return

print "Reassembled CRYPTO Data Length: #{#reassembled_crypto_data}"

-- Step 6: Parse TLS ClientHello and Extract SNI
print "\n-- Parsing TLS ClientHello and Extracting SNI --"

-- Parse TLS Handshake message header from reassembled CRYPTO data
hs_header, ch_offset = handshake.parse reassembled_crypto_data, 1

unless hs_header
  print "Error: Failed to parse TLS Handshake message header."
  return

print "Handshake Message Type: #{handshake.message_types[hs_header.type] or "Unknown"} (0x#{string.format "%02x", hs_header.type})"
print "Handshake Message Length: #{hs_header.len}"

assert hs_header.type == handshake.message_types.client_hello, "Expected ClientHello message"

-- Parse ClientHello Message Structure
ch_obj, _ = hello.parse reassembled_crypto_data, ch_offset

unless ch_obj
  print "Error: Failed to parse ClientHello message structure."
  return

print "ClientHello Protocol Version: 0x#{string.format "%04x", ch_obj.version}"
print "ClientHello Extensions Block Length (raw): #{#ch_obj.extensions}"

-- Iterate Through Extensions to Find Server Name Indication (SNI)
sni_host = nil
for extension in handshake.iter_extensions ch_obj.extensions
  if extension.type == handshake.extensions.server_name
    print "  > Found Server Name Indication (SNI) Extension"
    sni_list = sni.parse extension.data
    if sni_list and sni_list.names and #sni_list.names > 0
      name_entry = sni_list.names[1]
      if name_entry and name_entry.type == sni.name_types.HOST_NAME
        sni_host = name_entry.name
        print "    SNI Host Name: #{sni_host}"
      else
        print "    Warning: First SNI entry not of type host_name or not found."
    else
      print "    Error: Failed to parse SNI data or no names found."
    break

print "\n--- End of QUIC SNI Parsing Tutorial ---"

print "\n--- Running Assertions ---"

-- Assertions for each frame's initial parsing
for i, frame in ipairs frames
  eth_frame, l3_offset = ethernet.parse frame
  ip_packet, l4_offset = ip.parse frame, l3_offset, eth_frame.protocol
  udp_dgram, l7_offset = udp.parse frame, l4_offset

  assert eth_frame, "L2: Ethernet frame #{i} should be parsed"
  assert eth_frame.protocol == ethernet.proto.IP4 or eth_frame.protocol == ethernet.proto.IP6, "L2: EtherType should be IP4 or IP6 for Frame #{i}"
  assert ip_packet, "L3: IP packet #{i} should be parsed"
  assert ip_packet.protocol == ip.proto.UDP, "L3: Protocol should be UDP for Frame #{i}"
  assert udp_dgram, "L4: UDP datagram #{i} should be parsed"
  assert udp_dgram.dpt == 443 or udp_dgram.spt == 443, "L4: UDP port should be 443 for Frame #{i}"

-- Assertions for QUIC packet processing
assert #quic_pkts == #frames, "Expected a QUIC packet for each frame"
for i, quic_pkt in ipairs quic_pkts
  assert quic_pkt, "L4: QUIC packet #{i} should be parsed"
  assert quic_pkt.type == quic.packet_type.INITIAL, "L4: QUIC Packet Type should be INITIAL for packet #{i}"

-- Reassembly Assertions
assert reassembled_crypto_data, "Reassembled CRYPTO data should not be nil"
-- Add a more specific length assertion if known

-- TLS ClientHello Assertions
assert hs_header, "TLS Handshake header should be parsed"
assert hs_header.type == handshake.message_types.client_hello, "Handshake Type should be client_hello"
assert ch_obj, "ClientHello object should be parsed"
assert ch_obj.version == 0x0303, "ClientHello Protocol Version mismatch (expected TLS 1.2)"

-- SNI Assertion
assert sni_host, "SNI: SNI host should be extracted"
assert sni_host == "example.com", "SNI: Extracted SNI host mismatch"

print "All assertions passed successfully!"
