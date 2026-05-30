const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');

var baseUrl = "http://localhost:3000"
var logout_post_redirect_uri_value = baseUrl + "/logout.html";
var headless = true;
var waitTime = 10000;

async function populateMetadata(driver, discovery_endpoint) {
  console.log("Entering populateMetadata().");
  console.log("Find oidc_discovery_endpoint.");
  oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
  console.log("Find btn_oidc_discovery_endpoint.");
  btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
  console.log("Find btn_oidc_populate_meta_data.");
  btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

  // Wait until page is loaded
  console.log("Wait for oidc_discovery_endpoint.");
  await driver.wait(until.elementLocated(oidc_discovery_endpoint), waitTime);
  console.log("Wait for oidc_discovery_endpoint.");
  await driver.wait(until.elementIsVisible(driver.findElement(oidc_discovery_endpoint)), waitTime);

  // Enter discovery endpoint
  console.log("Find & Clear oidc_discovery_endpoint.");
  await driver.findElement(oidc_discovery_endpoint).clear();
  console.log("Find & Send Keys discovery_endpoint.");
  await driver.findElement(oidc_discovery_endpoint).sendKeys(discovery_endpoint);
  console.log("Find & Click btn_oidc_discovery_endpoint.");
  await driver.findElement(btn_oidc_discovery_endpoint).click();

  // Populate metadata
  console.log("Find btn_oidc_populate_meta_data.");
  await driver.wait(until.elementLocated(btn_oidc_populate_meta_data), waitTime);
  console.log("Find btn_oidc_populate_meta_data.");
  await driver.wait(until.elementIsVisible(driver.findElement(btn_oidc_populate_meta_data)), waitTime);
  console.log("Execute script.");
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(btn_oidc_populate_meta_data));
  console.log("Find & Click btn_oidc_populate_meta_data.");
  await driver.findElement(btn_oidc_populate_meta_data).click();
  console.log("Leaving populateMetadata().");
}

async function verifyAccessToken(access_token, client_id, scope, user, audience, issuer) {
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
  assert.strictEqual(decoded_access_token.payload.sub, user, "Access token SUB does not match user ID: access_token.payload.sub=" + decoded_access_token.payload.sub + " , user=" + user);
  assert.strictEqual(decoded_access_token.payload.aud, audience, "Access token aud does not match " + audience);
  assert.strictEqual(decoded_access_token.payload.iss, issuer, "Access token iss does not match " + issuer);
  assert.strictEqual(decoded_access_token.payload.given_name, client_id, "Access token given_name does not match.");
  assert.strictEqual(decoded_access_token.payload.family_name, client_id, "Access token family_name does not match.");
  assert.strictEqual(decoded_access_token.payload.email, `${client_id}@iyasec.io`, "Access token email does not match.");
  assert.strictEqual(decoded_access_token.payload.typ, "Bearer", "Access Token typ does not match.");
}

async function getAccessToken(driver, client_id, client_secret, scope, username, password) {
  console.log("Entering getAccessToken().");

  // Select Resource Owner Password Credential grant type on debugger.html
  console.log("Find authorization_grant_type.");
  const authorization_grant_type = By.id("authorization_grant_type");
  await driver.wait(until.elementLocated(authorization_grant_type), waitTime);
  console.log("Select 'OAuth2 Resource Owner Password Credential Grant'.");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Resource Owner Password Credential Grant');

  // Wait for debugger2.html to load
  console.log("Wait for token_client_id on debugger2.html.");
  const token_client_id = By.id("token_client_id");
  await driver.wait(until.elementLocated(token_client_id), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

  // Select OIDC No
  console.log("Click noCheckOIDCArtifacts.");
  const noCheckOIDCArtifacts = By.id("noCheckOIDCArtifacts");
  await driver.wait(until.elementLocated(noCheckOIDCArtifacts), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(noCheckOIDCArtifacts));
  await driver.findElement(noCheckOIDCArtifacts).click();

  // Select PKCE No
  console.log("Click usePKCE-no.");
  const usePKCENo = By.id("usePKCE-no");
  await driver.wait(until.elementLocated(usePKCENo), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(usePKCENo));
  await driver.findElement(usePKCENo).click();

  // Collapse config pane
  console.log("Collapse config pane.");
  const config_expand_button = By.id("config_expand_button");
  await driver.wait(until.elementLocated(config_expand_button), waitTime);
  const configBtnEl = await driver.findElement(config_expand_button);
  const configBtnVal = await configBtnEl.getAttribute("value");
  if (configBtnVal === "Hide") {
    await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", configBtnEl);
    await configBtnEl.click();
  }

  // Select POST auth style
  console.log("Click token_postAuthStyleCheckToken.");
  const token_postAuthStyleCheckToken = By.id("token_postAuthStyleCheckToken");
  await driver.wait(until.elementLocated(token_postAuthStyleCheckToken), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(token_postAuthStyleCheckToken));
  await driver.findElement(token_postAuthStyleCheckToken).click();

  // Select Back-end initiation
  console.log("Click token_initiateFromBackEnd.");
  const token_initiateFromBackEnd = By.id("token_initiateFromBackEnd");
  await driver.wait(until.elementLocated(token_initiateFromBackEnd), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(token_initiateFromBackEnd));
  await driver.findElement(token_initiateFromBackEnd).click();

  // Fill in credentials
  console.log("Fill token_client_id.");
  await driver.findElement(token_client_id).clear();
  await driver.findElement(token_client_id).sendKeys(client_id);

  console.log("Fill token_client_secret.");
  const token_client_secret = By.id("token_client_secret");
  await driver.findElement(token_client_secret).clear();
  await driver.findElement(token_client_secret).sendKeys(client_secret);

  console.log("Fill token_scope.");
  const token_scope = By.id("token_scope");
  await driver.findElement(token_scope).clear();
  await driver.findElement(token_scope).sendKeys(scope);

  console.log("Fill token_username.");
  const token_username = By.id("token_username");
  await driver.wait(until.elementLocated(token_username), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_username)), waitTime);
  await driver.findElement(token_username).clear();
  await driver.findElement(token_username).sendKeys(client_id);

  console.log("Fill token_password.");
  const token_password = By.id("token_password");
  await driver.wait(until.elementLocated(token_password), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_password)), waitTime);
  await driver.findElement(token_password).clear();
  await driver.findElement(token_password).sendKeys(password);

  // Click Get Token
  console.log("Click token_btn.");
  const token_btn = By.className("token_btn");
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(token_btn));
  await driver.findElement(token_btn).click();

  // Get access token result
  async function waitForVisibility(element) {
    console.log("Waiting for " + element);
    await driver.wait(until.elementLocated(element), waitTime);
    console.log("Waiting for " + element + "is visible.");
    await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
    console.log("Returning " + element);
    return element;
  }

  console.log("Find token_access_token.");
  token_access_token = By.id("token_access_token");

  console.log("Find display_token_error_form_texarea1.");
  display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  let visibleAccessTokenElement = await Promise.any([
    waitForVisibility(token_access_token),
    waitForVisibility(display_token_error_form_textarea1)
  ]);

  console.log("Begin returning token.");
  return await driver.findElement(visibleAccessTokenElement).getAttribute("value");

  console.log("Leaving getAccessToken().");
}

async function logout(driver) {
  console.log("Entering logout().");
  console.log("Find logout Button");
  logout_button = By.id("logout_btn");
  console.log("Find logout_post_redirect_uri.");
  logout_post_redirect_uri = By.id("logout_post_redirect_uri");
  console.log("Wait for logout_post_redirect_uri.");
  await driver.wait(until.elementLocated(logout_post_redirect_uri), waitTime);
  console.log("Wait for logout_post_redirect_uri to be visible.");
  await driver.findElement(logout_post_redirect_uri).clear();
  await driver.wait(until.elementIsVisible(driver.findElement(logout_post_redirect_uri)), waitTime);
  console.log("Set post_redirect_uri for logout.");
  await driver.findElement(logout_post_redirect_uri).sendKeys(logout_post_redirect_uri_value);
  console.log("Click logout_btn.");
  await driver.findElement(logout_button).click();

//  console.log("Wait for kc_logout.");
//  kc_logout = By.id("kc-logout");
//  await driver.wait(until.elementLocated(kc_logout), waitTime);
//  console.log("Wait for kc-logout to be visible.");
//  await driver.wait(until.elementIsVisible(driver.findElement(kc_logout)), waitTime);

//  console.log("Click kc_logout.");
//  await driver.findElement(kc_logout).click();

  console.log("Click link to return to the front page of the debugger.");
  returnToDebugLink = By.partialLinkText('Return to debugger');
  await driver.wait(until.elementLocated(returnToDebugLink), waitTime);
  await driver.findElement(returnToDebugLink).click();

//  console.log("Find authz_expand_button.");
//  authz_expand_button = By.id("authz_expand_button");
//  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
//  console.log("Waiting for authz_expand_button to be visible.");
//  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), waitTime);

//  console.log("Find client_id.");
//  client_id = By.id("client_id");
//  console.log("Wait for client_id");
//  await driver.findElement(client_id);
//  console.log("Wait for client_id to be visible.");
//  await driver.wait(until.elementIsVisible(driver.findElement(client_id)), waitTime);
}

async function test() {
  const options = new chrome.Options();
  if(headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    console.log("Starting Test run.");
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    const username = process.env.USER;
    const password = client_id;
    const audience = process.env.AUDIENCE;
    console.log("Set environment variables.");

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(username, "USER environment variable is not set.");
    assert(audience, "AUDIENCE environment variable is not set.");
    console.log("Assertions completed successfully.");

    console.log("Starting driver.get() run.");
    await driver.get(baseUrl);
    console.log("Completed driver.get() run.");
    console.log("Starting populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    console.log("Completed populateMetadata().");
    console.log("Retrieve access_token.");
    const access_token = await getAccessToken(driver, client_id, client_secret, scope, username, password);
    console.log("Found access_token=" + access_token);
    console.log("Calling verifyAccessToken().");
    await verifyAccessToken(access_token, client_id, scope, username, "account", audience);
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
  .name('oauth2_resource_owner_password_credentials_grant')
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
