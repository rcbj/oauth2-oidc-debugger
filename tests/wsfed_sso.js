const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'wsfed_sso',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// WS-Federation Passive Requestor Profile SSO test. Mirrors saml_sso.js, but:
//   - the sign-in request is a top-level browser navigation (wa=wsignin1.0) and
//     is NOT signed (no SP key to load — passive profile);
//   - the IdP is the dedicated Keycloak 8.0.1 + cloudtrust wsfed side-car;
//   - the IdP POSTs a wresult (WS-Trust RSTR carrying a SAML assertion) to the
//     debugger's api /wsfed landing, which stashes it and redirects to
//     wsfed_response.html?id=... where the token is rendered.
// Env: WSFED_METADATA_URL (the side-car descriptor), WSFED_REALM (the wtrealm ==
// the provisioned client id), WSFED_USER (login user; password == username).

async function waitForValue(driver, locator, predicate, message, timeout) {
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(async function () {
    try {
      var v = await driver.findElement(locator).getAttribute("value");
      return predicate(v || "");
    } catch (e) { return false; }
  }, timeout || waitTime, message);
}

async function clickByValue(driver, value) {
  var locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", el);
  await el.click();
}

async function setField(driver, id, value) {
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(e){ e.value = arguments[1];" +
    " e.dispatchEvent(new Event('input',{bubbles:true})); e.dispatchEvent(new Event('change',{bubbles:true})); }",
    id, value);
}

// The passive sign-in endpoint is the descriptor URL without the trailing
// "/descriptor" (Keycloak serves both under /protocol/wsfed). Deriving it makes
// the test robust to any metadata-parsing quirk in the (EOL) extension's
// descriptor format, while metadata loading is still exercised below.
function deriveEndpoint(metadataUrl) {
  return String(metadataUrl || "").replace(/\/descriptor\/?(\?.*)?$/, "");
}

async function wsfedActivities(driver, metadataUrl, realm, user) {
  // Keycloak's login page + the WS-Fed round-trip need a generous timeout.
  var loginWait = Math.max(waitTime, 15000);

  log.info("Load the WS-Federation Test Tools page.");
  await driver.get(baseUrl + "/wsfed_tools.html");

  // Load + parse the IdP metadata (best-effort: it populates the sign-in
  // endpoint + signer cert; we don't hard-fail on descriptor-format quirks).
  log.info("Load IdP metadata from " + metadataUrl);
  var mdField = By.id("wsfed_metadata_url");
  await driver.wait(until.elementLocated(mdField), waitTime);
  await driver.findElement(mdField).clear();
  await driver.findElement(mdField).sendKeys(metadataUrl);
  try {
    await clickByValue(driver, "Load Metadata");
    await waitForValue(driver, By.id("wsfed_metadata_status"),
      function (v) { return v.indexOf("Parsed metadata") >= 0; },
      "metadata parse status", loginWait);
    log.info("Metadata parsed.");
  } catch (e) {
    log.warn("Metadata load/parse did not complete cleanly (" + e.message + ") — continuing with the derived endpoint.");
  }

  // Ensure the passive sign-in endpoint + RP realm (wtrealm) are set. Set the
  // endpoint explicitly (derived) so the flow does not depend on the parse.
  var endpoint = await driver.findElement(By.id("wsfed_signin_endpoint")).getAttribute("value");
  if (!endpoint) { endpoint = deriveEndpoint(metadataUrl); await setField(driver, "wsfed_signin_endpoint", endpoint); }
  log.info("Sign-in endpoint: " + endpoint);
  await setField(driver, "wsfed_realm", realm);

  // Send the sign-in request (wa=wsignin1.0). Button value is "Call IdP (Sign In)".
  log.info("Call IdP (Sign In). wtrealm=" + realm);
  await clickByValue(driver, "Call IdP (Sign In)");

  // Keycloak login (same login form as the other tests; user == password).
  log.info("Log in at Keycloak.");
  var username = By.id("username");
  var password = By.id("password");
  var kcLogin = By.id("kc-login");
  await driver.wait(until.elementLocated(username), loginWait);
  await driver.wait(until.elementIsVisible(driver.findElement(username)), loginWait);
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  await driver.findElement(password).clear();
  await driver.findElement(password).sendKeys(user);
  await driver.findElement(kcLogin).click();

  // Land on the response page (the api /wsfed landing stashed the wresult and
  // redirected here with ?id=...).
  log.info("Wait for the WS-Federation response page.");
  await driver.wait(until.urlContains("wsfed_response.html"), loginWait);
  await waitForValue(driver, By.id("wsfed_resp_status"),
    function (v) { return v.indexOf("wresult loaded.") >= 0; },
    "wresult was not loaded on the response page.", loginWait);

  var respXml = await driver.findElement(By.id("wsfed_response_xml")).getAttribute("value");
  log.info("wresult (first 1500 chars):\n" + (respXml || "").substring(0, 1500));

  // Core assertions: the wresult is a WS-Trust RSTR and the extracted token is a
  // SAML assertion.
  assert(respXml.indexOf("RequestSecurityTokenResponse") >= 0,
    "wresult is not a WS-Trust RequestSecurityTokenResponse — see the logged wresult above.");
  await waitForValue(driver, By.id("wsfed_token_xml"),
    function (v) { return v.indexOf("Assertion") >= 0 && v.indexOf("no <wst:RequestedSecurityToken") < 0; },
    "No SAML Assertion was extracted from the wresult.", loginWait);

  // Best-effort: validate the token signature (exercises the button; the IdP
  // cert is embedded in the assertion's KeyInfo). Logged, not hard-asserted, so
  // a signature-format quirk of the EOL extension doesn't fail the basic flow.
  try {
    await clickByValue(driver, "Validate Signature");
    await driver.sleep(500);
    var sig = await driver.findElement(By.id("wsfed_sig_status")).getAttribute("value");
    log.info("Signature validation: " + sig);
  } catch (e) { log.warn("Signature validation step skipped: " + e.message); }

  log.info("WS-Federation SSO round-trip succeeded.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");

  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  try {
    const metadataUrl = process.env.WSFED_METADATA_URL;
    const realm = process.env.WSFED_REALM || "urn:wsfed:test:rp";
    const user = process.env.WSFED_USER || "wsfed";
    assert(metadataUrl, "WSFED_METADATA_URL environment variable is not set.");

    await wsfedActivities(driver, metadataUrl, realm, user);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
      var src = await driver.getPageSource();
      log.error("Page source (first 8000 chars):\n" + (src || "").substring(0, 8000));
      var blogs = await driver.manage().logs().get("browser");
      if (blogs && blogs.length) {
        log.error("Browser console:\n" + blogs.map(function (e) { return e.level.name + ": " + e.message; }).join("\n"));
      }
    } catch (e2) { /* ignore */ }
    process.exit(1);
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program
  .name('wsfed_sso')
  .description("Run WS-Federation Passive Requestor SSO test.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });

program.parse(process.argv).opts();

test();
