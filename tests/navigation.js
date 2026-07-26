const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require('commander');
const assert = require("assert");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'navigation',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// Landing page: the two protocol-choice cards.
var OAUTH2_CARD = By.css('a.landing-card[href="/debugger.html"]');
var SAML_CARD = By.css('a.landing-card[href="/saml_request.html"]');
var WSTRUST_CARD = By.css('a.landing-card[href="/wstrust_tools.html"]');
var CHOICES = By.css('.landing-choices');
// The header "Home" nav link (returns to the landing page).
var HOME_LINK = By.css('.header_debugger a[href="/index.html"]');

async function waitVisible(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(locator)), waitTime);
  return driver.findElement(locator);
}

// M.N.O, shown in the footer of every page. The build number must be identical
// everywhere — it identifies the build being served, not the moment of the
// request — so the first one seen becomes the expectation for the rest.
var VERSION_RE = /^v\d+\.\d+\.\d+$/;
var seenVersion = null;
async function checkFooterVersion(driver, where) {
  var el = await waitVisible(driver, By.css('.footer-version'));
  var text = (await el.getText()).trim();
  assert.ok(VERSION_RE.test(text),
    "[" + where + "] the footer should show a M.N.O version, found: '" + text + "'");
  var title = await el.getAttribute('title');
  assert.ok(/Build \S+ — built /.test(title || ''),
    "[" + where + "] the version tooltip should carry the build provenance, found: '" + title + "'");
  if (seenVersion === null) { seenVersion = text; log.info("Footer version: " + text); }
  else {
    assert.strictEqual(text, seenVersion,
      "[" + where + "] every page must report the same build: " + text + " vs " + seenVersion);
  }
}

async function click(driver, locator) {
  var elArtifact = await waitVisible(driver, locator);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", elArtifact);
  await elArtifact.click();
}

async function navigationActivities(driver) {
  // 1. Hit the base URL -> the landing page (site root serves index.html).
  log.info("Load the base URL (landing page).");
  await driver.get(baseUrl);
  await waitVisible(driver, CHOICES);
  log.info("Landing page loaded (protocol choices present).");
  await checkFooterVersion(driver, "landing page");

  // 2. Choose the OAuth2 / OIDC debugger -> debugger.html.
  log.info("Click the OAuth2 / OIDC debugger card.");
  await click(driver, OAUTH2_CARD);
  await driver.wait(until.urlContains("debugger.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("authorization_grant_type")), waitTime);
  log.info("Landed on debugger.html.");
  await checkFooterVersion(driver, "debugger.html");

  // 3. Click Home -> back to the landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);
  log.info("Back on the landing page.");

  // 4. Choose the SAML debugger -> saml_request.html.
  log.info("Click the SAML debugger card.");
  await click(driver, SAML_CARD);
  await driver.wait(until.urlContains("saml_request.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("saml_metadata_url")), waitTime);
  log.info("Landed on saml_request.html.");
  await checkFooterVersion(driver, "saml_request.html");

  // 5. Return to Home -> landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);
  log.info("Back on the landing page.");

  // 6. Choose the WS-Trust debugger -> wstrust_tools.html.
  log.info("Click the WS-Trust debugger card.");
  await click(driver, WSTRUST_CARD);
  await driver.wait(until.urlContains("wstrust_tools.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("wst_sts_url")), waitTime);
  log.info("Landed on wstrust_tools.html.");
  await checkFooterVersion(driver, "wstrust_tools.html");

  // 7. Return to Home -> landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);
  await checkFooterVersion(driver, "landing page (return)");
  log.info("Back on the landing page. Navigation test succeeded.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages under coverage.
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
    await navigationActivities(driver);
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
  .name('navigation')
  .description("Run basic navigation test.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });

program.parse(process.argv).opts();

test();
