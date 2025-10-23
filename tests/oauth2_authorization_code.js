const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
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

async function getAccessToken(driver, client_id, client_secret, scope, pkce_enabled) {
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

  // Select client credential login type
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OIDC Authorization Code Flow(code)');
  await driver.wait(until.elementLocated(usePKCE_yes), 10000);
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_yes)), 10000);
  await driver.wait(until.elementLocated(usePKCE_no), 10000);
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_no)), 10000);

  if (pkce_enabled) {
    await driver.findElement(usePKCE_yes).click();
  } else {
    await driver.findElement(usePKCE_no).click();
  }

  await driver.wait(until.elementLocated(authz_expand_button), 10000);
  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), 10000);
  await driver.findElement(authz_expand_button).click();
  await driver.wait(until.elementLocated(client_id_), 10000);
  await driver.wait(until.elementIsVisible(driver.findElement(client_id_)), 10000);

  // Submit credentials
  await driver.findElement(client_id_).clear();
  await driver.findElement(client_id_).sendKeys(client_id);
  await driver.findElement(scope_).clear();
  await driver.findElement(scope_).sendKeys(scope);
  await driver.findElement(btn_authorize).click();

  // Login to Keycloak
  try {
    await driver.wait(until.elementLocated(keycloak_username), 10000);
    await driver.wait(until.elementIsVisible(driver.findElement(keycloak_username)), 10000);
  } catch (error) {
    authz_error_report = await driver.findElement(By.id("authz-error-report"));
    authz_error_report_paragraphs = await authz_error_report.findElements(By.css("p"));
    throw new Error(await authz_error_report_paragraphs[authz_error_report_paragraphs.length - 1].getText());
  }

  await driver.findElement(keycloak_username).clear();
  await driver.findElement(keycloak_username).sendKeys(client_id);
  await driver.findElement(keycloak_password).clear();
  await driver.findElement(keycloak_password).sendKeys(client_id);
  await driver.findElement(keycloak_kc_login).click();

  // Submit credentials (again)
  await driver.wait(until.elementLocated(token_client_id), 10000);
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), 10000);

  await driver.findElement(token_client_id).clear();
  await driver.findElement(token_client_id).sendKeys(client_id);
  await driver.findElement(token_client_secret).clear();
  await driver.findElement(token_client_secret).sendKeys(client_secret);
  await driver.findElement(token_scope).clear();
  await driver.findElement(token_scope).sendKeys(scope);
  await driver.findElement(token_btn).click();

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

async function test() {
  const options = new chrome.Options();
  options.addArguments("--headless");
  options.addArguments("--no-sandbox");
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

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

    await driver.get("http://localhost:3000");
    await populateMetadata(driver, discovery_endpoint);
    let access_token = await getAccessToken(driver, client_id, client_secret, scope, pkce_enabled);
    await verifyAccessToken(access_token, client_id, scope, user);
    console.log("Test completed successfully.")
  } catch (error) {
    console.log(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
}

test();
