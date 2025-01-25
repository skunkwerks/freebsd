#!/usr/bin/env lua

-- Example using the Lua FileSystem module
local lfs = require "lfs"

-- Directory listing
print("Directory contents:")
for file in lfs.dir(".") do
    if file ~= "." and file ~= ".." then
        local attrs = lfs.attributes(file)
        print(string.format("%s: %d bytes (%s)", 
            file, attrs.size, attrs.mode))
    end
end

-- Create and remove a directory
local test_dir = "test_dir"
lfs.mkdir(test_dir)
print("\nCreated directory:", test_dir)
lfs.rmdir(test_dir)
print("Removed directory:", test_dir)

-- File attributes
local attr = lfs.attributes("/etc/passwd")
print("\nFile attributes for /etc/passwd:")
for name, value in pairs(attr) do
    print(name, value)
end
