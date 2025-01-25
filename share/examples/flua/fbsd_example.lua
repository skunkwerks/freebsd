#!/usr/bin/env lua

-- Example using the FreeBSD-specific module
local fbsd = require "fbsd"

print("Running 'ls -l' using fbsd.exec:")
-- This will replace the current process
fbsd.exec("/bin/ls", {"-l"})

-- Note: Code after exec() won't be reached as the process is replaced
