#!/usr/bin/env lua

-- Example using the UCL module
local ucl = require "ucl"

-- Create a new parser
local parser = ucl.parser_new()

-- Add some UCL configuration data
local config = [[
# Server configuration
server {
    host = "localhost";
    port = 8080;
    
    # Array of allowed origins
    origins [
        "https://example.com",
        "https://test.com"
    ];
    
    # Nested object
    ssl {
        enabled = true;
        cert = "/path/to/cert.pem";
    }
}
]]

-- Parse the configuration
parser:add_chunk(config)

-- Get the resulting object
local obj = parser:get_object()

-- Access the parsed data
print("Server Configuration:")
print("Host:", obj.server.host)
print("Port:", obj.server.port)
print("\nAllowed Origins:")
for _, origin in ipairs(obj.server.origins) do
    print("-", origin)
end
print("\nSSL Settings:")
print("Enabled:", obj.server.ssl.enabled)
print("Certificate:", obj.server.ssl.cert)
