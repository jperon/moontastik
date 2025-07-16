--- Reassembler
-- @module reassembler

--- Creates a new stream reassembler instance.
-- The reassembler is a closure that accepts data chunks and attempts to
-- reconstruct a contiguous data stream.
-- @function reassembler
-- @treturn function: The reassembler closure.
-- @usage
--   -- MoonScript
--   stream1 = require"reassembler"!
--
--   -- Add chunks (self is the data, off is offset, last is boolean)
--   stream1 "world", 6, true          -- Add "world" at offset 6, this is the last chunk
--   stream1 "Hello ", 0               -- Add "Hello " at offset 0
--
--   complete = stream1 " ", 5         -- Add " " at offset 5
--   assert complete == "Hello world"  -- if complete_data is a string, the stream is fully reassembled.
-- @usage
--   -- Lua
--   local new_reassembler = require "reassembler" -- Assuming module name is reassembler.moon
--   local reassemble_stream1 = new_reassembler()
--
--   -- Add chunks (self is the data, off is offset, last is boolean)
--   reassemble_stream1("world", 6, true)    -- Add "world" at offset 6, this is the last chunk
--   reassemble_stream1("Hello ", 0, false)  -- Add "Hello " at offset 0
--
--   local complete_data = reassemble_stream1(" ", 5, false)  -- Add " " at offset 5
--   assert(complete == "Hello world")  -- if complete_data is a string, the stream is fully reassembled.

->
  buf, data = {}, ""
  next_off, last_off = 0, nil

  --- Adds a data chunk to the reassembler.
  -- This is the reassembler closure itself.
  -- @function closure
  -- @tparam string self The data chunk being added.
  -- @tparam number off The offset of this data chunk within the stream.
  -- @tparam boolean last True if this is the last chunk of the stream, false otherwise.
  -- @treturn string The fully reassembled stream data if the stream is complete.
  -- @treturn boolean `false` if the stream is not yet complete and no error occurred.
  -- @treturn nil, string `nil` and an error message if an error occurred (e.g., "duplicate last", "beyond end").
  -- @within reassembler
  (off, last) =>
    print "REASSEMBLER DEBUG: off=#{off}, last=#{tostring(last)}, type(last)=#{type(last)}, data_len=#{#@}"
    if last_off
      print "REASSEMBLER DEBUG: last_off is set, checking for duplicate last"
      return nil, "duplicate last" if last
      return nil, "beyond end" if off >= last_off
    last_off = off + #@ if last
    buf[off] = @ if off

    while true
      chunk = buf[next_off]
      break if not chunk
      data ..= chunk
      buf[next_off] = nil
      next_off += #chunk

    return next_off == last_off and data
