#!/usr/bin/env node

"use strict";

process.title = "hap-proxy";

// Find the HomeBridge lib
const path = require("path");
const fs = require("fs");
const lib = path.join(path.dirname(fs.realpathSync(__filename)), "../lib");

require(lib + "/cli");
