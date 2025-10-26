const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");

var logs = {};

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
  await driver.wait(until.elementLocated(oidc_discovery_endpoint), 10000);
  console.log("Wait for oidc_discovery_endpoint.");
  await driver.wait(until.elementIsVisible(driver.findElement(oidc_discovery_endpoint)), 10000);

  // Enter discovery endpointA
  console.log("Find & Clear oidc_discovery_endpoint.");
  await driver.findElement(oidc_discovery_endpoint).clear();
  console.log("Find & Send Keys discovery_endpoint.");
  await driver.findElement(oidc_discovery_endpoint).sendKeys(discovery_endpoint); 
  console.log("Find & Click btn_oidc_discovery_endpoint.");
  await driver.findElement(btn_oidc_discovery_endpoint).click();

  // Populate metadata
  console.log("Find btn_oidc_populate_meta_data.");
  await driver.wait(until.elementLocated(btn_oidc_populate_meta_data), 10000);
  console.log("Find btn_oidc_populate_meta_data.");
  await driver.wait(until.elementIsVisible(driver.findElement(btn_oidc_populate_meta_data)), 10000);
  console.log("Execute script.");
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(btn_oidc_populate_meta_data));
  console.log("Find & Click btn_oidc_populate_meta_data.");
  await driver.findElement(btn_oidc_populate_meta_data).click();
  console.log("Leaving populateMetadata().");
}

async function getAccessToken(driver, client_id, client_secret, scope) {
  console.log("Entering getAccessToken().");
  console.log("Find authorization_grant_type.");
  authorization_grant_type = By.id("authorization_grant_type");
  console.log("Find token_client_id.");
  token_client_id = By.id("token_client_id");
  console.log("Find token_client_secret.")
  token_client_secret = By.id("token_client_secret");
  console.log("Find token_scope.");
  token_scope = By.id("token_scope");
  console.log("Find token_btn.");
  token_btn = By.className("token_btn");
  console.log("Find token_btn.");
  token_access_token = By.id("token_access_token");
  console.log("Find display_token_error_form_textarea1.");
  display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  // Select client credential login type
  console.log("Find visible text 'OAuth2 Client Credential'.");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Client Credential');
  console.log("Find token_client_id element.");
  await driver.wait(until.elementLocated(token_client_id), 10000);
  console.log("Wait until element is visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), 10000);

  // Submit credentials
  console.log("Find token_client_id & clear.");
  await driver.findElement(token_client_id).clear();
  console.log("Find token_client_id and send keys.");
  await driver.findElement(token_client_id).sendKeys(client_id);
  console.log("Find token_client_secret & clear.");
  await driver.findElement(token_client_secret).clear();
  console.log("Find token_client_secret and send keys.");
  await driver.findElement(token_client_secret).sendKeys(client_secret);
  console.log("Find token_scope and clear.");
  await driver.findElement(token_scope).clear();
  console.log("Find token_scope and send keys.");
  await driver.findElement(token_scope).sendKeys(scope);
  console.log("Find token_btn and click().");
  await driver.findElement(token_btn).click();

  // Get access token result
  async function waitForVisibility(element) {
    console.log("element: " + element);
    console.log("Waiting for element: " + element);
//    console.log("Dump of current console.");
//    logs = await driver.executeScript('return window.console.log;');
//    console.log(logs);
    console.log("------------------------------------------");
    print(driver.page_source);
    console.log("------------------------------------------");
    await driver.wait(until.elementLocated(element), 10000);
    console.log("Waiting for element2: " + element);
    await driver.wait(until.elementIsVisible(driver.findElement(element)), 10000);
    console.log("element: " + element);
    return element;
  }

  try {
    let visibleAccessTokenElement = await Promise.any([
      waitForVisibility(token_access_token),
      waitForVisibility(display_token_error_form_textarea1)
    ]);
    console.log("Returning visibleAccessTokenElement value.");
    return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
  } catch (e) {
    console.log("An error occurred: " + e.message);
  }
}

async function verifyAccessToken(access_token, client_id, scope) {
  async function compareScopes(scope1, scope2) {
    scope1 = scope1.split(" ");
    scope2 = scope2.split(" ");

    return scope2.every(element => scope1.includes(element));
  }

  let decoded_access_token = jwt.decode(access_token, { complete: true });
  let response_text = access_token.match(/responseText: (.*)/);

  assert.notStrictEqual(decoded_access_token, null, "Cannot decode access token. Request result: " + (response_text ? response_text[1] : "no response text"));
  assert.strictEqual(decoded_access_token.payload.client_id, client_id, "Access token client ID does not match client ID.");
  assert.strictEqual(await compareScopes(decoded_access_token.payload.scope, scope), true, "Access token scope does not match scope.");
}

async function test() {
  const options = new chrome.Options();
  options.addArguments("--headless");
  options.addArguments("--no-sandbox");
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    console.log("Starting Test run.");
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    console.log("Set environment variables.");

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    console.log("Assertions completed successfully.");

    console.log("Starting driver.get() run.");
    await driver.get("http://client:3000");
    console.log("Setup console logger.");
    logs = await driver.executeScript('return window.console.log;');
    console.log(logs);
    console.log("Completed driver.get() run.");
    console.log("Starting populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    console.log("Completed populateMetadata().");
    console.log("Retrieve access_token.");
    let access_token = await getAccessToken(driver, client_id, client_secret, scope);
    console.log("Obtained token: " + access_token);
    console.log("Validating token.");
    await verifyAccessToken(access_token, client_id, scope);
    console.log("Token validated.");
    console.log("Test completed successfully.")
  } catch (error) {
    console.log(error.message);
    console.log(logs);
    process.exit(1);
  } finally {
    await driver.quit();
  }
}

test();
