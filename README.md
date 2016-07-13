# OpenConext-idensys

[![Build Status](https://travis-ci.org/OpenConext/OpenConext-idensys.svg)](https://travis-ci.org/OpenConext/OpenConext-idensys)
[![codecov.io](https://codecov.io/gh/OpenConext/OpenConext-idensys/coverage.svg)](https://codecov.io/gh/OpenConext/OpenConext-idensys)

Idensys is a SAML Proxy acting as a Identity Provider in the OpenConext SAML Federation and as a ServiceProvider for idensys - through
digidentity.

The Proxy behaviour can be configured in order for the Proxy to be used as a generic IdP-SP SAML proxy with hooks
for authnResponse 'enrichment'.

## [Getting started](#getting-started)

### [System Requirements](#system-requirements)

- Java 7
- Maven 3

### [Building and running](#building-and-running)

This project uses Spring Boot and Maven. To run locally, type:

```bash
mvn spring-boot:run
```

When developing, it's convenient to just execute the applications main-method, which is in [Application](src/main/java/idensys/Application.java).

## [SAML metadata](#saml-metadata)

The Idensys metadata is generated and accessible on [http://localhost:8080/sp/metadata](http://localhost:8080/sp/metadata)
and [http://localhost:8080/idp/metadata](http://localhost:8080/idp/metadata). The metadata is cached and refreshed every 24 hours. This
can be configured:

```yml
proxy:
  # duration of metadata cache (1 day)
  validity_duration_metadata_ms: 86400000
```

The Service Providers allowed to connect to the Idensys are provided in a Metadata feed configured in ```application.yml```:

```yml
serviceproviders:
  feed: https://engine.test2.surfconext.nl/authentication/sp/metadata
```
By default - but easily changed / overridden - all Service Providers in the SAML metadata feed
are allowed to connect. See [ServiceProviderFeedParser](src/main/java/idensys/saml/ServiceProviderFeedParser.java).

The feed can also be a file url when developing locally:

```yml
serviceproviders:
  feed: classpath:saml/eb.sp.metadata.xml
```

When developing locally or deploying in a test environment Idensys can be configured to allow any SP to connect by
setting `serviceproviders.allow_unknown` to `true`. This is not recommended and the default is `false`.

```yml
serviceproviders:
  allow_unknown: true
```

The metadata of the IdentityProvider (currently we don't allow more then one and assume that a possible WAYF is the
responsibility of the actual IdentityProvider proxied by Idensys) must be provided in the ```application.yml```

```yml
idp:
# metadata_url: https://eherkenning.digidentity-accept.eu/hm/eh19/metadata
  metadata_url: classpath:saml/idensys.metadata.saml.xml
```

## [Service Catalog](#service_catalog)
The [Service Catalog](https://afsprakenstelsel.etoegang.nl/display/as/Service+catalog) for this Proxy DV can be found at:

[https://idensys.test.surfconext.nl/service/catalog](https://idensys.test.surfconext.nl/service/catalog)

The content is served from [this file](src/main/resources/service_catalog.xml). When you make changes don't forget to replace the Signature.

## [Testing](#testing)
There are integration tests that spin off a running application and these can also be run inside the IDE.

There is a test SP endpoint that requires authentication against the configured IdP and displays all SAML attributes received:

[http://localhost:8080/test](http://localhost:8080/test)

The production SAML flow with a Idensys is depicted in [this image](src/main/resources/static/images/idensys.001.jpeg).

## [Private signing key and public certificate](#signing-keys)

(Note: When using Ansible with the create_new_environment.sh script you can skip these steps)

The SAML Spring Security library needs a private DSA key / public certificate pair for the Idensys IdP / SP which can be generated.

```bash
openssl req -subj '/O=SURFnet, CN=Idensys/' -newkey rsa:2048 -new -x509 -days 3652 -nodes -out idensys.crt -keyout idensys.pem
```

The Java KeyStore expects a pkcs8 DER format for RSA private keys so we have to re-format that key:

```bash
openssl pkcs8 -nocrypt  -in idensys.pem -topk8 -out idensys.der
```
 
Remove the whitespace, heading and footer from the idensys.crt and idensys.der:

```bash
cat idensys.der |head -n -1 |tail -n +2 | tr -d '\n'; echo
cat idensys.crt |head -n -1 |tail -n +2 | tr -d '\n'; echo
```

Above commands work on linux distributions. On mac you can issue the same command with `ghead` after you install `coreutils`:

```bash
brew install coreutils

cat idensys.der |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
cat idensys.crt |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
```

Add the idensys key pair to the application.yml file:

```yml
# Idensys
proxy:
  private_key: ${output from cleaning the der file}
  certificate: ${output from cleaning the crt file}
```

## [Deployment](#deployment)
The Idensys application has documented [properties](src/main/resources/application.yml) packaged inside the jar. When deploying
to a non-local environment ensure you have application.yml properties outside of the packaged jar to override
the Idensys configuration.

### Ansible

A complete VM can be deployed with ansible. This project uses the Ansible "environment" setup as described in
https://github.com/pmeulen/ansible-tools. Secrets are encrypted using keyczar (see [environment.conf](ansible/environments/template/environment.conf))

To prepare for a deploy you must first create a new "environment" and customise it:

1. Install the dependencies for using ansible-tools

2. Create a new environment:  
  `cd ansible`  
  `./scripts/create_new_environment.sh <environment dir>`  
  
3. Update the inventory and groups_vars in the generated environment to match your setup

4. Deploy using ansible:  
   `ansible-playbook idensys.yml -i <environment dir>/inventory`  
   To only update the Spring Boot jar append `--tags "idensys"`

## [Releases](#releases)

Releases are uploaded to the build server where Ansible picks them up. To upload a new release run:

```bash
mvn deploy
```

You will need the configure the username and password for the repositories `openconext-releases` and `openconext-snapshots` in your
~/.m2/settings.xml. Use [settings.example.xml](src/test/resources/templates/settings.example.xml) as a template.
