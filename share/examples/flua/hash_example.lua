#!/usr/bin/env lua

-- Example using the hash module for SHA256
local hash = require "hash"

-- Create a new SHA256 hash
local h = hash.sha256.new()

-- Update with some data
h:update("Hello, ")
h:update("World!")

-- Get the hex digest
print("SHA256:", h:hexdigest())

-- Show digest and block sizes
print("Digest size:", hash.sha256.digest_size, "bytes")
print("Block size:", hash.sha256.block_size, "bytes")
