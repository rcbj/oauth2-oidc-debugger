## Publicly Accessible Hosted Sites
The [IDPTools.com](https://idptools.com) is a static content website; there is no backend API endpoints that need to be secured.

This creates potential complications with CORS. Depending on the Identity Provdier, it may be necessary to run the containerized version of this application on your local device so that requests can be proxied through the bundled API layer.

## SSRF

This project intentionally accepts arbitrary Identity Provider endpoints because that is the core purpose of the debugger.

The project does **not** maintain an allow-list of trusted identity providers.

Instead, SSRF mitigations focus on preventing abuse:

* Only HTTP/HTTPS
* block private and loopback ranges
* request timeouts
* response size limits

Only point this protocol debugger at Identity Providers that you trust.
