const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const jwt = require("jsonwebtoken");
const assert = require("assert");

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

async function getAccessToken(driver, client_id, client_secret, scope) {
  authorization_grant_type = By.id("authorization_grant_type");
  token_client_id = By.id("token_client_id");
  token_client_secret = By.id("token_client_secret");
  token_scope = By.id("token_scope");
  btn1 = By.className("btn1");
  token_access_token = By.id("token_access_token");
  display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  // Select client credential login type
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Client Credential');
  await driver.wait(until.elementLocated(token_client_id), 10000);
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), 10000);

  // Submit credentials
  await driver.findElement(token_client_id).clear();
  await driver.findElement(token_client_id).sendKeys(client_id);
  await driver.findElement(token_client_secret).clear();
  await driver.findElement(token_client_secret).sendKeys(client_secret);
  await driver.findElement(token_scope).clear();
  await driver.findElement(token_scope).sendKeys(scope);
  await driver.findElement(btn1).click();

  // Get access token result
  async function waitForVisibility(element) {
    await driver.wait(until.elementLocated(element), 10000);
    await driver.wait(until.elementIsVisible(driver.findElement(element)), 10000);
    return element;
  }

  let visibleAccessTokenElement = await Promise.any([
    waitForVisibility(token_access_token),
    waitForVisibility(display_token_error_form_textarea1)
  ]);

  return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
}

async function verifyAccessToken(access_token, client_id, scope) {
  let decoded_access_token = jwt.decode(access_token, { complete: true });

  assert.notStrictEqual(decoded_access_token, null, "Cannot decode access token. Request result: " + access_token.match(/responseText: (.*)/)[1]);
  assert.strictEqual(decoded_access_token.payload.client_id, client_id, "Access token client ID does not match client ID.");
  assert.strictEqual(decoded_access_token.payload.scope, scope, "Access token scope does not match scope.");
}

async function test() {
  const driver = await new Builder().forBrowser("chrome").build();

  try {
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");

    await driver.get("http://localhost:3000");
    await populateMetadata(driver, discovery_endpoint);
    let access_token = await getAccessToken(driver, client_id, client_secret, scope);
    await verifyAccessToken(access_token, client_id, scope);
  } catch (error) {
    console.log(error.message);
  } finally {
    await driver.quit();
  }
}

test();