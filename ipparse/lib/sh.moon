--- A module for executing shell commands.
--
-- This module provides a convenient way to execute shell commands directly from MoonScript/Lua.
-- Commands can be chained using dot notation, and arguments are passed as function parameters.
--
-- @module sh
:open, :popen = io
:tmpname = os
:concat = table

read = => if @
  ret = @read"*a"
  @close! and ret

-- @usage
-- local sh = require "sh"
--
-- -- Execute a simple command
-- local output, err, exit_code = sh.ls "-la"
-- print(output)
--
-- -- Move a file
-- sh.mv "old_file.txt", "new_file.txt"
--
-- @field __call (function) Executes the constructed shell command.
-- @field __index (function) Creates the callable object for command name.
sh = {}
--- Executes the shell command.
-- This metamethod is invoked when the `sh` object is called as a function.
-- It constructs the full command string, executes it, and captures its standard output,
-- standard error, and exit code.
-- @param ... Arguments to be passed to the shell command. These are concatenated with spaces.
-- @treturn string The standard output of the command.
-- @treturn string The standard error of the command.
-- @treturn number The exit code of the command.
sh.__call = (...) =>
  err = tmpname!
  cmd = @cmd .. " " .. concat({...}, " ") .. " 2>" .. err
  p = popen cmd
  error "Failed to execute command: " .. cmd if not p
  output = p\read"*a"
  ok, _, ret = p\close!
  output, not ok and read(open err), ret, popen("rm " .. err)\close! and nil
--- Handles command chaining.
-- This metamethod is called when an attempt is made to access a field of the `sh` object.
-- It allows for building up a command string by chaining multiple parts, e.g., `sh.git.status`.
-- @tparam string cmd Command name.
-- @treturn table A new `sh` table instance with the `cmd` field updated to include the new part.
sh.__index = (cmd) =>
  setmetatable :cmd, sh

setmetatable sh, sh
