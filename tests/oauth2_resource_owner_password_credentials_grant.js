const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');

var baseUrl = "http://localhost:3000"
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
  await driver.findElement(token_username).sendKeys(username);

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

  console.log("Leaving getAccessToken().");
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
    const username = process.env.USERNAME;
    const password = username;
    console.log("Set environment variables.");

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(username, "USERNAME environment variable is not set.");
    console.log("Assertions completed successfully.");

    console.log("Starting driver.get() run.");
    await driver.get(baseUrl);
    console.log("Completed driver.get() run.");
    console.log("Starting populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    console.log("Completed populateMetadata().");
    console.log("Retrieve access_token.");
    await getAccessToken(driver, client_id, client_secret, scope, username, password);
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
    }
    if(!!options.browser) {
      console.log("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
