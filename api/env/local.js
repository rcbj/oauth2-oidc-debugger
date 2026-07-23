var config = {
  apiUrl: "http://localhost:4000",
  uiUrl: "http://localhost:3000",
  hostname: "0.0.0.0",
  port: "4000",
  logLevel: "debug",
  // SAML Service Provider identity (this debugger acting as an SP).
  spEntityId: "http://localhost:3000/saml/sp",
  acsUrl: "http://localhost:4000/samlacs",
  sloUrl: "http://localhost:4000/samlslo"
};

module.exports = config;
