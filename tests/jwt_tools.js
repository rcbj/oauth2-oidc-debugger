const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'jwt_tools',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
// Client-side crypto (key generation, signing, JWE, format conversion) is fast
// but can exceed the 2s element-wait on a busy CI host, so results get a
// generous, separate timeout.
var cryptoWait = Math.max(waitTime, 15000);

// ---- small Selenium helpers -----------------------------------------------
async function click(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", el);
  await el.click();
}

async function setInput(driver, locator, text) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await el.clear();
  await el.sendKeys(text);
}

async function getValue(driver, locator) {
  return await driver.findElement(locator).getAttribute("value");
}

// Wait until a field's value satisfies pred(value), then return the value.
async function waitForValue(driver, locator, pred, msg, timeout) {
  await driver.wait(async function () {
    try {
      var v = await driver.findElement(locator).getAttribute("value");
      return pred(v || "");
    } catch (e) {
      return false;
    }
  }, timeout || cryptoWait, msg);
  return await getValue(driver, locator);
}

// Click a toggle-switch by its wrapping <label> (the checkbox itself is
// display:none, so it is not directly clickable).
async function clickToggle(driver, checkboxId) {
  await click(driver, By.xpath("//label[.//input[@id='" + checkboxId + "']]"));
}

function onclickBtn(fn) {
  return By.xpath("//input[@onclick=\"return jwt_tools." + fn + "();\"]");
}

async function addCustomClaim(driver, name, value, type) {
  log.info("Adding custom claim: name=" + name + ", value=" + value + ", type=" + type);
  await setInput(driver, By.id("custom_claim_name"), name);
  await setInput(driver, By.id("custom_claim_value"), value);
  await new Select(driver.findElement(By.id("custom_claim_type"))).selectByValue(type);
  await new Select(driver.findElement(By.id("custom_claim_target"))).selectByValue("jwt_tools_payload");
  await click(driver, onclickBtn("addClaim"));
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf('"' + name + '"') !== -1; },
    "Claim '" + name + "' was not added to the JWT Payload.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    log.info("Starting Test run.");

    // ---- Load the debugger main page --------------------------------------
    log.info("Load debugger.html.");
    await driver.get(baseUrl + "/debugger.html");

    // ---- Expand the Tools pane and open JWT Tools -------------------------
    log.info("Expand the Tools pane.");
    await click(driver, By.id("tools_expand_button"));

    log.info("Click the JWT Tools link.");
    var jwtToolsLink = By.css('a[href="/jwt_tools.html?from=debugger.html"]');
    await driver.wait(until.elementLocated(jwtToolsLink), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(jwtToolsLink)), waitTime);
    await click(driver, jwtToolsLink);

    // Wait for the JWT Tools page (default payload is populated on load).
    log.info("Wait for JWT Tools page to load.");
    await waitForValue(driver, By.id("jwt_tools_payload"),
      function (v) { return v.indexOf('"iss"') !== -1; },
      "JWT Tools page did not load / default payload not populated.");

    // ---- Pane 1: add custom claims + RFC compliance -----------------------
    await addCustomClaim(driver, "customString", "hello world", "string");
    await addCustomClaim(driver, "customNumber", "42", "number");
    await addCustomClaim(driver, "customBool", "true", "boolean");

    log.info("Click Check RFC Compliance.");
    await click(driver, onclickBtn("checkCompliance"));
    var compliance = await waitForValue(driver, By.id("compliance_output"),
      function (v) { return v.indexOf("PASS") !== -1; },
      "Compliance output was not produced.");
    log.info("Compliance output:\n" + compliance);
    assert.ok(compliance.indexOf("PASS") !== -1, "Expected at least one PASS in compliance output.");
    assert.ok(compliance.indexOf("FAIL") === -1,
      "Compliance output contained a FAIL:\n" + compliance);
    log.info("Compliance check passed with no FAIL entries.");

    // ---- Pane 2: signing (JWS) --------------------------------------------
    log.info("Generate signing keys.");
    await click(driver, onclickBtn("generateSigningKeys"));
    await waitForValue(driver, By.id("sign_public_key"),
      function (v) { return v.indexOf("BEGIN PUBLIC KEY") !== -1; },
      "Signing public key (PEM) was not generated.");

    log.info("Toggle keys to JWK.");
    await clickToggle(driver, "sign_key_jwk");
    await waitForValue(driver, By.id("sign_private_key"),
      function (v) { return v.trim().charAt(0) === "{"; },
      "Signing private key did not convert to JWK.");

    log.info("Toggle keys back to PEM.");
    await clickToggle(driver, "sign_key_jwk");
    await waitForValue(driver, By.id("sign_private_key"),
      function (v) { return v.indexOf("BEGIN PRIVATE KEY") !== -1; },
      "Signing private key did not convert back to PEM.");

    log.info("Download signing keys in PEM format.");
    await new Select(driver.findElement(By.id("sign_ks_format"))).selectByValue("pem");
    await click(driver, onclickBtn("downloadSigningKeys"));
    await waitForValue(driver, By.id("sign_status"),
      function (v) { return v.indexOf("Downloaded PEM") !== -1; },
      "Signing keys were not downloaded in PEM format.");

    log.info("Generate Signed JWT.");
    await click(driver, onclickBtn("signJWT"));
    var signedJwt = await waitForValue(driver, By.id("jwt_tools_signed"),
      function (v) { return v.split(".").length === 3; },
      "Signed JWT was not produced.");
    log.info("Signed JWT produced (" + signedJwt.length + " chars).");

    log.info("Select X.509 verification type.");
    await new Select(driver.findElement(By.id("jwt_verification_type"))).selectByValue("x509");
    // The X.509 verification key should auto-fill from the generated public key.
    await waitForValue(driver, By.id("jwt_verification_key"),
      function (v) { return v.indexOf("BEGIN PUBLIC KEY") !== -1; },
      "X.509 verification key was not auto-populated with the public key.");

    log.info("Verify the signature.");
    await click(driver, onclickBtn("verifyJWT"));
    var verifyOut = await waitForValue(driver, By.id("jwt_verification_output"),
      function (v) { return v.indexOf("Signature Verified:") !== -1; },
      "Verification output was not produced.");
    log.info("Verification output: " + verifyOut);
    assert.ok(verifyOut.indexOf("Signature Verified: true") !== -1,
      "Expected signature verification to succeed. Output: " + verifyOut);
    log.info("Signature verification succeeded.");

    // ---- Pane 3: encryption (JWE) -----------------------------------------
    log.info("Generate encryption keys.");
    await click(driver, onclickBtn("generateEncryptionKeys"));
    await waitForValue(driver, By.id("jwe_public_key"),
      function (v) { return v.indexOf("BEGIN PUBLIC KEY") !== -1; },
      "Encryption public key (PEM) was not generated.");

    log.info("Toggle encryption keys to JWK.");
    await clickToggle(driver, "jwe_key_jwk");
    await waitForValue(driver, By.id("jwe_private_key"),
      function (v) { return v.trim().charAt(0) === "{"; },
      "Encryption private key did not convert to JWK.");

    log.info("Toggle encryption keys back to PEM.");
    await clickToggle(driver, "jwe_key_jwk");
    await waitForValue(driver, By.id("jwe_private_key"),
      function (v) { return v.indexOf("BEGIN PRIVATE KEY") !== -1; },
      "Encryption private key did not convert back to PEM.");

    log.info("Download encryption keys.");
    await click(driver, onclickBtn("downloadEncryptionKeys"));
    await waitForValue(driver, By.id("jwe_status"),
      function (v) { return v.indexOf("Downloaded") !== -1; },
      "Encryption keys were not downloaded.");

    // Capture the payload that will be encrypted (the signed JWT from pane 2).
    var plaintext = (await getValue(driver, By.id("jwe_plaintext"))).trim();
    assert.ok(plaintext.length > 0, "Payload to Encrypt is empty.");

    log.info("Encrypt the JWT.");
    await click(driver, onclickBtn("encryptJWT"));
    await waitForValue(driver, By.id("jwt_tools_jwe"),
      function (v) { return v.split(".").length === 5; },
      "JWE (5-part compact) was not produced.");

    log.info("Decrypt the JWT.");
    await click(driver, onclickBtn("decryptJWT"));
    var decrypted = await waitForValue(driver, By.id("jwe_decrypt_output"),
      function (v) { return v.trim().length > 0; },
      "Decryption output was not produced.");

    assert.strictEqual(decrypted.trim(), plaintext,
      "Decryption output does not match the Payload to Encrypt value.");
    log.info("Decryption output matches the Payload to Encrypt value.");

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program
  .name('jwt_tools')
  .description("Run JWT Tools UI test.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
  )
  .action((options) => {
    if (!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
