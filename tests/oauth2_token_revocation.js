const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_token_revocation',
                                level: process.env.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000"
var headless = true;
var waitTime = 10000;

// The OAuth2/OIDC test IdP (Keycloak) is frequently configured with a
// self-signed certificate. Token revocation verification below makes direct
// HTTP calls to the IdP from this test process, so relax TLS validation the
// same way the debugger lets the user disable SSL validation for testing.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

async function populateMetadata(driver, discovery_endpoint) {
  oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
  btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
  btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

  // Wait until page is loaded
  await driver.wait(until.elementLocated(oidc_discovery_endpoint), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(oidc_discovery_endpoint)), waitTime);

  // Enter discovery endpoint
  await driver.findElement(oidc_discovery_endpoint).clear();
  await driver.findElement(oidc_discovery_endpoint).sendKeys(discovery_endpoint);
  await driver.findElement(btn_oidc_discovery_endpoint).click();

  // Populate metadata
  await driver.wait(until.elementLocated(btn_oidc_populate_meta_data), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(btn_oidc_populate_meta_data)), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(btn_oidc_populate_meta_data));
  await driver.findElement(btn_oidc_populate_meta_data).click();
}

async function getAccessToken(driver, client_id, client_secret, scope, pkce_enabled) {
  log.info("Entering getAccessToken().");
  authorization_grant_type = By.id("authorization_grant_type");
  usePKCE_yes = By.id("usePKCE-yes");
  usePKCE_no = By.id("usePKCE-no");
  authz_expand_button = By.id("authz_expand_button");
  client_id_ = By.id("client_id");
  scope_ = By.id("scope");
  token_client_id = By.id("token_client_id");
  token_client_secret = By.id("token_client_secret");
  token_scope = By.id("token_scope");
  btn_authorize = By.css("input[type=\"submit\"][value=\"Authorize\"]");
  keycloak_username = By.id("username");
  keycloak_password = By.id("password");
  keycloak_kc_login = By.id("kc-login");
  token_btn = By.className("token_btn");
  token_access_token = By.id("token_access_token");
  display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  // Select OIDC authorization code flow login type
  log.info("Set authorization_grant_type to OIDC Authorization Code Flow(code).");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OIDC Authorization Code Flow(code)');
  await driver.wait(until.elementLocated(usePKCE_yes), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_yes)), waitTime);
  await driver.wait(until.elementLocated(usePKCE_no), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_no)), waitTime);

  if (pkce_enabled) {
    await driver.findElement(usePKCE_yes).click();
  } else {
    await driver.findElement(usePKCE_no).click();
  }

  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), waitTime);
  await driver.findElement(authz_expand_button).click();
  await driver.wait(until.elementLocated(client_id_), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(client_id_)), waitTime);

  // Submit credentials
  await driver.findElement(client_id_).clear();
  await driver.findElement(client_id_).sendKeys(client_id);
  await driver.findElement(scope_).clear();
  await driver.findElement(scope_).sendKeys(scope);
  redirect_uri = By.id("redirect_uri");
  await driver.findElement(redirect_uri).clear();
  await driver.findElement(redirect_uri).sendKeys(baseUrl + "/callback");
  await driver.findElement(btn_authorize).click();

  // Login to Keycloak
  try {
    await driver.wait(until.elementLocated(keycloak_username), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(keycloak_username)), waitTime);
  } catch (error) {
    log.error("Unable to log into keycloak.");
    authz_error_report = await driver.findElement(By.id("authz-error-report"));
    authz_error_report_paragraphs = await authz_error_report.findElements(By.css("p"));
    throw new Error(await authz_error_report_paragraphs[authz_error_report_paragraphs.length - 1].getText());
  }

  await driver.findElement(keycloak_username).clear();
  await driver.findElement(keycloak_username).sendKeys(client_id);
  await driver.findElement(keycloak_password).clear();
  await driver.findElement(keycloak_password).sendKeys(client_id);
  await driver.findElement(keycloak_kc_login).click();

  // Submit credentials (again) on the token exchange form
  await driver.wait(until.elementLocated(token_client_id), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

  await driver.findElement(token_client_id).clear();
  await driver.findElement(token_client_id).sendKeys(client_id);
  await driver.findElement(token_client_secret).clear();
  await driver.findElement(token_client_secret).sendKeys(client_secret);
  await driver.findElement(token_scope).clear();
  await driver.findElement(token_scope).sendKeys(scope);
  token_redirect_uri = By.id("token_redirect_uri");
  await driver.findElement(token_redirect_uri).clear();
  await driver.findElement(token_redirect_uri).sendKeys(baseUrl + "/callback");
  await driver.findElement(token_btn).click();

  // Get access token result
  async function waitForVisibility(element) {
    await driver.wait(until.elementLocated(element), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
    return element;
  }

  let visibleAccessTokenElement = await Promise.any([
    waitForVisibility(token_access_token),
    waitForVisibility(display_token_error_form_textarea1)
  ]);

  let access_token = await driver.findElement(visibleAccessTokenElement).getAttribute("value");
  let response_text = access_token.match(/responseText: (.*)/);
  assert.notStrictEqual(jwt.decode(access_token, { complete: true }), null,
    "Cannot obtain access token. Request result: " + (response_text ? response_text[1] : "no response text"));

  // Capture the refresh token from the Token Endpoint results pane.
  let refresh_token = "";
  try {
    refresh_token = await driver.findElement(By.id("token_refresh_token")).getAttribute("value");
  } catch (e) {
    log.warn("No refresh token element found.");
  }
  assert(refresh_token && refresh_token.length > 0,
    "No refresh token was returned. Ensure the scope includes offline_access.");

  log.info("Obtained access token and refresh token.");
  return { access_token, refresh_token };
}

// Drive the new Token Revocation pane: click the "Revoke Token" button rendered
// next to the token of the given type (which populates the pane AND submits the
// revocation in one action), then wait for the results pane to report a
// successful (HTTP 200) RFC 7009 response.
async function revokeTokenViaUI(driver, type) {
  log.info("Revoking token via UI. type=" + type);
  const revokeBtn = By.css(`input.revoke_token_btn[data-revoke-type='${type}']`);
  await driver.wait(until.elementLocated(revokeBtn), waitTime);
  const btnEl = await driver.findElement(revokeBtn);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", btnEl);
  await driver.wait(until.elementIsVisible(btnEl), waitTime);
  await btnEl.click();

  const resultArea = By.id("revocation_result_textarea");
  await driver.wait(until.elementLocated(resultArea), waitTime);
  await driver.wait(async () => {
    try {
      const v = await driver.findElement(resultArea).getAttribute("value");
      return !!v && v.indexOf("HTTP Status: 200") !== -1;
    } catch (e) {
      return false;
    }
  }, waitTime, "Token revocation result did not report HTTP 200 for type=" + type);

  const finalText = await driver.findElement(resultArea).getAttribute("value");
  log.info("Revocation result (" + type + "): " + finalText.replace(/\n/g, " | "));
  assert(finalText.indexOf("HTTP Status: 200") !== -1,
    "Revocation call for " + type + " did not return HTTP 200.");
  return finalText;
}

async function getDiscovery(discovery_endpoint) {
  const res = await fetch(discovery_endpoint);
  assert(res.ok, "Failed to fetch discovery document: HTTP " + res.status);
  return await res.json();
}

// Calls the UserInfo endpoint with the access token. Returns the HTTP status.
async function callUserInfo(userinfo_endpoint, access_token) {
  const res = await fetch(userinfo_endpoint, {
    method: "GET",
    headers: { "Authorization": "Bearer " + access_token }
  });
  return res.status;
}

// Attempts a Refresh Token grant. Returns the HTTP status.
async function callRefreshGrant(token_endpoint, client_id, client_secret, refresh_token) {
  const params = new URLSearchParams();
  params.append("grant_type", "refresh_token");
  params.append("client_id", client_id);
  if (client_secret) {
    params.append("client_secret", client_secret);
  }
  params.append("refresh_token", refresh_token);
  const res = await fetch(token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString()
  });
  return res.status;
}

async function test() {
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  try {
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    // Public (PKCE) clients may have no secret; treat it as optional.
    const client_secret = process.env.CLIENT_SECRET || "";
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    let pkce_enabled = process.env.PKCE_ENABLED;

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");

    if (pkce_enabled === "true") {
      pkce_enabled = true;
    } else if (pkce_enabled === "false") {
      pkce_enabled = false;
    } else {
      log.info("PKCE_ENABLED must be true or false.");
      process.exit(1);
    }

    log.info("Fetching discovery document to resolve token/userinfo/revocation endpoints.");
    const discovery = await getDiscovery(discovery_endpoint);
    const token_endpoint = discovery.token_endpoint;
    const userinfo_endpoint = discovery.userinfo_endpoint;
    const revocation_endpoint = discovery.revocation_endpoint;
    assert(token_endpoint, "Discovery document is missing token_endpoint.");
    assert(userinfo_endpoint, "Discovery document is missing userinfo_endpoint.");
    assert(revocation_endpoint, "Discovery document is missing revocation_endpoint (RFC 7009 / RFC 8414).");
    log.info("revocation_endpoint=" + revocation_endpoint);

    log.info("Kicking off test.");
    await driver.get(baseUrl);
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken().");
    const { access_token, refresh_token } = await getAccessToken(driver, client_id, client_secret, scope, pkce_enabled);

    // Sanity check: the freshly issued access token should be valid BEFORE
    // revocation, so the post-revocation failure is meaningful.
    log.info("Verifying access token is valid before revocation (UserInfo call).");
    const preStatus = await callUserInfo(userinfo_endpoint, access_token);
    log.info("Pre-revocation UserInfo status: " + preStatus);
    assert.strictEqual(preStatus, 200,
      "Access token was not valid before revocation (UserInfo returned " + preStatus + ").");

    // Revoke the access token through the new Token Revocation pane.
    log.info("Revoking the access token via the UI.");
    await revokeTokenViaUI(driver, "access");

    // Revoke the refresh token through the new Token Revocation pane.
    log.info("Revoking the refresh token via the UI.");
    await revokeTokenViaUI(driver, "refresh");

    // Verify the access token is now rejected by the UserInfo endpoint.
    log.info("Verifying the access token has been revoked (UserInfo call).");
    const postUserInfoStatus = await callUserInfo(userinfo_endpoint, access_token);
    log.info("Post-revocation UserInfo status: " + postUserInfoStatus);
    assert.notStrictEqual(postUserInfoStatus, 200,
      "Access token still valid after revocation (UserInfo returned 200).");

    // Verify the refresh token can no longer be exchanged for new tokens.
    log.info("Verifying the refresh token has been revoked (Refresh Token grant).");
    const refreshStatus = await callRefreshGrant(token_endpoint, client_id, client_secret, refresh_token);
    log.info("Post-revocation Refresh grant status: " + refreshStatus);
    assert.notStrictEqual(refreshStatus, 200,
      "Refresh token still valid after revocation (token endpoint returned 200).");

    log.info("Both the access token and refresh token were successfully revoked.");
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
  .name('oauth2_token_revocation')
  .description("Run test.")
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
