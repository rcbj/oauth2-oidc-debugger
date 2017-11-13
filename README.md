# OAuth2 + OpenID Connect Debugger
This is a simple OAuth2 and OpenID Connect (OIDC) debugger (test tool) that I created as part of a Red Hat SSO blog post I created in November, 2017.  The blog post uses this debugger for testing the OpenID Connect setup.  So, checkout the blog for usage examples. This project builds a docker container that runs the debugger application.

The following OAuth2 Authorization Grants are supported:
* Authorization Code Grant
* Implicit Code Grant
* Resource Owner Password Grant
* Client Credentials Grant

The following OpenID Connect Authentication Flows are supported
* Authorization Code Flow (use Authorization Code Grant option and scope="openid profile")

Support the remaining OIDC Authentication Flows will be implemented in the future.

So far, this tool has been tested with Red Hat SSO v7.1.  I'll add support for Azure Active Directory soon.

## Getting Started
From a bash command prompt on Fedora or RHEL 7.x, run the following::
``` yum install git
 git clone https://github.com/rcbjLevvel/oauth2-oidc-debugger.git
 yum install docker
 system start docker
 yum install docker-compose
 cd oauth-oidc-debugger
 docker-compose build
 docker-compose up
```
Open your favorite browser and enter "http://localhost:3000" in the address bar.

Choose the OAuth2 grant that you want to test.

Enter the Authorization Endpoint.
Enter the Token Endpoint.
Enter the other parameters as required by the authorization grant that you are interested in.

See the blog posts referenced above for more information.

On other systems, the commands needed to start the debugger in a local docker container will be similar.

## Prerequisites

To run this project you will need to install docker and docker-compose.

## Building the docker image
``` yum install git
 git clone https://github.com/rcbjLevvel/oauth2-oidc-debugger.git
 yum install docker
 system start docker
 yum install docker-compose
 cd oauth-oidc-debugger
 docker-compose build`
```
## Authors

Robert C. Broeckelmann Jr. - Initial work

## License

This project is licensed under the Apache 2.0 License - see the LICENSE.md file for details

## Acknowledgments
Thanks to the [APICast (3Scale API Management Gateway OAuth2 Example](https://github.com/3scale/apicast/tree/master/examples/oauth2)for being the starting point for this experiment.
