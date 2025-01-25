#!/usr/bin/env lua

-- Example using the fetch module to download content
local fetch = require "fetch"

-- GET request example
local response = fetch.get_url("https://www.freebsd.org")
if response then
    print("Fetched FreeBSD homepage, size:", #response)
end

-- POST request example
local data = "key=value"
local response = fetch.post_url("https://httpbin.org/post", data)
if response then
    print("POST response:", response)
end
