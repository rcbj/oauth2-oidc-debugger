# OAuth2 + OpenID Connect Debugger
This is a simple OAuth2 and OpenID Connect (OIDC) debugger (test tool) that I created as part of a Red Hat SSO blog post I created in November, 2017.  The blog post uses this debugger for testing the OpenID Connect setup.  So, checkout the blog for usage examples. This project builds a docker container that runs the debugger application.

The following OAuth2 Authorization Grants are supported:
* Authorization Code Grant
* Implicit Code Grant
* Resource Owner Password Grant
* Client Credentials Grant

The following OpenID Connect Authentication Flows are supported
* Authorization Code Flow (use Authorization Code Grant option and scope="openid profile")

Support for the remaining OIDC Authentication Flows will be implemented in the future.

So far, this tool has been tested with:

* Red Hat SSO v7.1.  
* 3Scale SaaS with self-managed APICast Gateway
* Azure Active Directory

Note, that all configuration values except for the user password is written to local storage to prepopulate fields later.  If this is not desired, clear your browser's local storage for the debugger when done using.

## Getting Started
From a bash command prompt on Fedora or RHEL 7.x, run the following::
``` yum install git
 git clone https://github.com/rcbjLevvel/oauth2-oidc-debugger.git
 yum install docker
 system start docker
 cd oauth2-oidc-debugger/client
 docker build -t oauth2-oidc-debugger .
 docker run -p 3000:3000 --net=host oauth2-oidc-debugger 
```
On other systems, the commands needed to start the debugger in a local docker container will be similar.
### Running
Open your favorite browser and enter "http://localhost:3000" in the address bar.

Choose the OAuth2 grant that you want to test.

Enter the Authorization Endpoint.
Enter the Token Endpoint.
Enter the other parameters as required by the chosen grant.
If you need to provide a resource parameter, click the radio button.  Then, enter the desired resource parameter.
If using the Authorization Code Grant, click the Authorize button.  Authenticate the user.  Verify that the Code field is filled in below in the Token Step section.  Fill in the fields needed for  the token endpoint.  Click the Get Token button.
If using the Implicit Grant, click the the Authorize Button.  Authenticate the user.  The access_token will be listed below.
For the other grants, click the Get Token button.

See the blog posts referenced above for more information.

## Prerequisites

To run this project you will need to install docker.

## Building the docker image
``` yum install git
 git clone https://github.com/rcbjLevvel/oauth2-oidc-debugger.git
 yum install docker
 system start docker
 cd oauth2-oidc-debugger/client
 docker build -t oauth2-oidc-debugger .
 docker run -p 3000:3000 --net=host oauth2-oidc-debugger 
```
On other systems, the commands needed to start the debugger in a local docker container will be similar.

## Version History
* v0.1 - Red Hat SSO support including all OAuth2 Grants and OIDC Authorization Code Flow
* v0.2 - 3Scale + APICast support for all OAuth2 Grants and OIDC Authorization Code Flow
* v0.3 - Azure Active Directory support for OAuth2 Grans and OIDC Authorization Code Flow.  Added error reporting logic and support for optional resource parameter.  Added additional debug logging code in client.  Moved Token Endpoint interaction into server-side (Ruby/Sinatra/Docker); this was necessary because Azure Active Directory does not support CORS (making Javascript interaction from a browser impossible).  Disabled IdP server certificate validation in IdP call.
## Authors

Robert C. Broeckelmann Jr. - Initial work

## License

This project is licensed under the Apache 2.0 License - see the LICENSE.md file for details

## Acknowledgments
Thanks to the [APICast (3Scale API Management Gateway OAuth2 Example](https://github.com/3scale/apicast/tree/master/examples/oauth2)for being the starting point for this experiment.
