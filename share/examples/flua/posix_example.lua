#!/usr/bin/env lua

-- Example using the POSIX module
local posix = require "posix"

-- System information
local info = posix.sys.utsname.uname()
print("System Information:")
print("OS:", info.sysname)
print("Release:", info.release)
print("Version:", info.version)
print("Machine:", info.machine)

-- File operations
print("\nFile operations:")
local path = "test.txt"
local fd = posix.unistd.open(path, posix.fcntl.O_WRONLY + posix.fcntl.O_CREAT, "644")
posix.unistd.write(fd, "Hello from Lua POSIX!\n")
posix.unistd.close(fd)
print("Created file:", path)

-- Process operations
print("\nProcess information:")
print("PID:", posix.unistd.getpid())
print("Parent PID:", posix.unistd.getppid())

-- Pattern matching
print("\nPattern matching:")
local pattern = "*.lua"
local match = posix.fnmatch.fnmatch(pattern, "test.lua", 0)
print(string.format("'test.lua' matches '%s': %s", pattern, match and "yes" or "no"))
