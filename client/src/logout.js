// File: logout.js
// Author: Robert C. Broeckelmann Jr.
// Date: 12/28/2024
//Notes:
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'logout',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
window.onload = function() {
  log.debug("Entering onload function.");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
}

module.exports = {
 loadValuesFromLocalStorage,
};
