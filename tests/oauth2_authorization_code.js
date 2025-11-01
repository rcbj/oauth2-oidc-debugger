const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');

var baseUrl = "http://localhost:3000"
var logout_post_redirect_uri_value = baseUrl + "/logout.html";
var headless = true;

async function populateMetadata(driver, discovery_endpoint) {
  oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
  btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
  btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

  // Wait until page is loaded
  await driver.wait(until.elementLocated(oidc_discovery_endpoint), 10000);
  await driver.wait(until.elementIsVisible(driver.findElement(oidc_discovery_endpoint)), 10000);

  // Enter discovery endpoint
  await driver.findElement(oidc_discovery_endpoint).clear();
  await driver.findElement(oidc_discovery_endpoint).sendKeys(discovery_endpoint); 
  await driver.findElement(btn_oidc_discovery_endpoint).click();

  // Populate metadata
  await driver.wait(until.elementLocated(btn_oidc_populate_meta_data), 10000);
  await driver.wait(until.elementIsVisible(driver.findElement(btn_oidc_populate_meta_data)), 10000);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(btn_oidc_populate_meta_data));
  await driver.findElement(btn_oidc_populate_meta_data).click();
}

async function getAccessToken(driver, client_id, client_secret, scope, pkce_enabled) {
  console.log("Entering getAccessToken().");
  console.log("Find authorization_grant_type.");
  authorization_grant_type = By.id("authorization_grant_type");
  console.log("Find usePKCE-yes.");
  usePKCE_yes = By.id("usePKCE-yes");
  console.log("Find usePKCE-no.");
  usePKCE_no = By.id("usePKCE-no");
  console.log("Find authz_expand_button");
  authz_expand_button = By.id("authz_expand_button");
  console.log("Find client_id.");
  client_id_ = By.id("client_id");
  console.log("Find scope.");
  scope_ = By.id("scope");
  console.log("find token_client_id.");
  token_client_id = By.id("token_client_id");
  console.log("Find token_client_secret.");
  token_client_secret = By.id("token_client_secret");
  console.log("Find token_scope.");
  token_scope = By.id("token_scope");
  console.log("Find btn_authorize.");
  btn_authorize = By.css("input[type=\"submit\"][value=\"Authorize\"]");
  console.log("Find username.");
  keycloak_username = By.id("username");
  console.log("Find password.");
  keycloak_password = By.id("password");
  console.log("Find kc-login");
  keycloak_kc_login = By.id("kc-login");
  console.log("Find token_btn.");
  token_btn = By.className("token_btn");
  console.log("Find token_access_token.");
  token_access_token = By.id("token_access_token");
  console.log("Find display_token_error_form_texarea1.");
  display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  // Select client credential login type
  console.log("Set authorization_grant_type to OIDC Authorizaton Code Authentication Flow.");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OIDC Authorization Code Flow(code)');
  console.log("Waiting for usePKCE_yes");
  await driver.wait(until.elementLocated(usePKCE_yes), 10000);
  console.log("Waiting for usePKCE_yes to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_yes)), 10000);
  console.log("Waiting for usePKCE_no.");
  await driver.wait(until.elementLocated(usePKCE_no), 10000);
  console.log("Waiting for usePKCE to be visible");
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_no)), 10000);

  if (pkce_enabled) {
    console.log("Click usePKCE_yes.");
    await driver.findElement(usePKCE_yes).click();
  } else {
    console.log("Click usePKCE_no.");
    await driver.findElement(usePKCE_no).click();
  }

  console.log("Find authz_expand_button.");
  await driver.wait(until.elementLocated(authz_expand_button), 10000);
  console.log("Waiting for authz_expand_button to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), 10000);
  console.log("Click authz_expand_button.");
  await driver.findElement(authz_expand_button).click();
  console.log("Locate client_id_.");
  await driver.wait(until.elementLocated(client_id_), 10000);
  console.log("Find client_id_.");
  await driver.wait(until.elementIsVisible(driver.findElement(client_id_)), 10000);

  // Submit credentials
  console.log("Clear client_id_.");
  await driver.findElement(client_id_).clear();
  console.log("Set client_id value.");
  await driver.findElement(client_id_).sendKeys(client_id);
  console.log("Clear scope_.");
  await driver.findElement(scope_).clear();
  console.log("Set scope value.");
  await driver.findElement(scope_).sendKeys(scope);
  console.log("Find token_redirect_uri.");
  redirect_uri = By.id("redirect_uri");
  console.log("Clear redirect_uri.");
  await driver.findElement(redirect_uri).clear();
  console.log("Set redirect_uri value: redirect_uri=" + redirect_uri + ", redirect_uri=" + baseUrl + "/callback");
  await driver.findElement(redirect_uri).sendKeys(baseUrl + "/callback");
  console.log("Click btn_authorize button.");
  await driver.findElement(btn_authorize).click();

  // Login to Keycloak
  try {
    console.log("Wait for keycloak_username.");
    await driver.wait(until.elementLocated(keycloak_username), 10000);
    console.log("Wait for keycloak_username to be visible.");
    await driver.wait(until.elementIsVisible(driver.findElement(keycloak_username)), 10000);
  } catch (error) {
    console.log("Unable to log into keycloak.");
    authz_error_report = await driver.findElement(By.id("authz-error-report"));
    authz_error_report_paragraphs = await authz_error_report.findElements(By.css("p"));
    throw new Error(await authz_error_report_paragraphs[authz_error_report_paragraphs.length - 1].getText());
  }

  console.log("Clear keycloak_username.");
  await driver.findElement(keycloak_username).clear();
  console.log("Set keycloak_username value.");
  await driver.findElement(keycloak_username).sendKeys(client_id);
  console.log("Clear keycloak_password.");
  await driver.findElement(keycloak_password).clear();
  console.log("Set client_id value.");
  await driver.findElement(keycloak_password).sendKeys(client_id);
  console.log("Click keycloak_kc_login button.");
  await driver.findElement(keycloak_kc_login).click();

  // Submit credentials (again)
  console.log("Locate token_client_id.");
  await driver.wait(until.elementLocated(token_client_id), 10000);
  console.log("Wait for token_client_id to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), 10000);

  console.log("Clear token_client_id.");
  await driver.findElement(token_client_id).clear();
  console.log("Set token_client_id value.");
  await driver.findElement(token_client_id).sendKeys(client_id);
  console.log("Clear token_client_secret.");
  await driver.findElement(token_client_secret).clear();
  console.log("Set token_client_secret value.");
  await driver.findElement(token_client_secret).sendKeys(client_secret);
  console.log("Clear token_scope.");
  await driver.findElement(token_scope).clear();
  console.log("Set token_scope value.");
  await driver.findElement(token_scope).sendKeys(scope);
  console.log("Find token_redirect_uri.");
  token_redirect_uri = By.id("token_redirect_uri");
  console.log("Clear token_redirect_uri.");
  await driver.findElement(token_redirect_uri).clear();
  console.log("Set token_redirect_uri value: token_redirect_uri=" + token_redirect_uri + ", redirect_uri=" + baseUrl + "/callback");
  await driver.findElement(token_redirect_uri).sendKeys(baseUrl + "/callback");
  console.log("Click token_btn button.");
  await driver.findElement(token_btn).click();

  // Get access token result
  async function waitForVisibility(element) {
    console.log("Waiting for " + element);
    await driver.wait(until.elementLocated(element), 10000);
    console.log("Waiting for " + element + "is visible.");
    await driver.wait(until.elementIsVisible(driver.findElement(element)), 10000);
    console.log("Returning " + element);
    return element;
  }

  let visibleAccessTokenElement = await Promise.any([
    waitForVisibility(token_access_token),
    waitForVisibility(display_token_error_form_textarea1)
  ]);

  console.log("Begin returning token.");
  return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
}

async function verifyAccessToken(access_token, client_id, scope, user) {
  async function compareScopes(scope1, scope2) {
    scope1 = scope1.split(" ");
    scope2 = scope2.split(" ");

    return scope2.every(element => scope1.includes(element));
  }

  let decoded_access_token = jwt.decode(access_token, { complete: true });
  let response_text = access_token.match(/responseText: (.*)/);

  assert.notStrictEqual(decoded_access_token, null, "Cannot decode access token. Request result: " + (response_text ? response_text[1] : "no response text"));
  assert.strictEqual(decoded_access_token.payload.azp, client_id, "Access token AZP does not match client ID.");
  assert.strictEqual(await compareScopes(decoded_access_token.payload.scope, scope), true, "Access token scope does not match scope.");
  assert.strictEqual(decoded_access_token.payload.sub, user, "Access token SUB does not match user ID.");
  assert.strictEqual(decoded_access_token.payload.given_name, client_id, "Access token given_name does not match.");
  assert.strictEqual(decoded_access_token.payload.family_name, client_id, "Access token family_name does not match.");
  assert.strictEqual(decoded_access_token.payload.email, `${client_id}@iyasec.io`, "Access token email does not match.");
}

async function logout(driver) {
  console.log("Entering logout().");
  console.log("Find logout Button");
  logout_button = By.id("logout_btn");
  console.log("Find logout_post_redirect_uri.");
  logout_post_redirect_uri = By.id("logout_post_redirect_uri");
  console.log("Wait for logout_post_redirect_uri.");
  await driver.wait(until.elementLocated(logout_post_redirect_uri), 10000);
  console.log("Wait for logout_post_redirect_uri to be visible.");
  await driver.findElement(logout_post_redirect_uri).clear();
  await driver.wait(until.elementIsVisible(driver.findElement(logout_post_redirect_uri)), 10000);
  console.log("Set post_redirect_uri for logout.");
  await driver.findElement(logout_post_redirect_uri).sendKeys(logout_post_redirect_uri_value);
  console.log("Click logout_btn.");
  await driver.findElement(logout_button).click();

  console.log("Wait for kc_logout.");
  kc_logout = By.id("kc-logout");
  await driver.wait(until.elementLocated(kc_logout), 10000);
  console.log("Wait for kc-logout to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(kc_logout)), 10000);

  console.log("Click kc_logout.");
  await driver.findElement(kc_logout).click();

  console.log("Click link to return to the front page of the debugger.");
  returnToDebugLink = By.partialLinkText('Return to debugger');
  await driver.wait(until.elementLocated(returnToDebugLink), 10000);
  await driver.findElement(returnToDebugLink).click();

  console.log("Find authz_expand_button.");
  authz_expand_button = By.id("authz_expand_button");
  await driver.wait(until.elementLocated(authz_expand_button), 10000);
  console.log("Waiting for authz_expand_button to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), 10000);

  console.log("Find client_id.");
  client_id = By.id("client_id");
  console.log("Wait for client_id");
  await driver.findElement(client_id);
  console.log("Wait for client_id to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(client_id)), 10000);
}

async function test() {
  const options = new chrome.Options();
  if(headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  console.log("Enabling selinium logging.");
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
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    let pkce_enabled = process.env.PKCE_ENABLED

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");

    if (pkce_enabled === "true") {
      pkce_enabled = true;
    } else if (pkce_enabled === "false") {
      pkce_enabled = false;
    } else {
      console.log("PKCE_ENABLED must be true or false.");
      process.exit(1);
    }

    console.log("Kicking off test.");
    await driver.get(baseUrl);
    console.log("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    console.log("Calling getAccessToken().");
    let access_token = await getAccessToken(driver, client_id, client_secret, scope, pkce_enabled);
    console.log("Access token: " + access_token);
    console.log("Calling verifyAccessToken().");
    await verifyAccessToken(access_token, client_id, scope, user);
    console.log("Logging out.");
    await logout(driver);
    console.log("Test completed successfully.")
  } catch (error) {
    console.log(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program
  .name('oauth_authorization_code')
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
    if(!!options.url) {
      console.log("Setting url to " + options.url);
      baseUrl = options.url;
      logout_post_redirect_uri_value = options.url + "/logout.html";
    }
    if(!!options.browser) {
      console.log("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
