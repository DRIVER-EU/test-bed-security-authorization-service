[![Build Status](https://travis-ci.org/DRIVER-EU/test-bed-security-authorization-service.svg?branch=master)](https://travis-ci.org/DRIVER-EU/test-bed-security-authorization-service)

# Testbed Security Service for Authorization
REST service that provides access policy administration and evaluation to render a decision (Permit/Deny) for a given access request, aka *PAP* and *PDP* in [XACML](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html) standard.

## Docker build
Make sure the Docker service is running.
To build the Docker image:
```sh
$ mvn install dockerfile:build
```

## Docker run
Make sure the Docker service is running.
To run the Docker image:
```sh
$ docker run -v /path/to/test-bed-security-authorization-service/docker/application.properties:/application.properties -v /path/to/test-bed-security-authorization-service/target/test-classes:/opt/driver-testbed-sec-authz-service -p 8080:8080 -t authzforce/driver-testbed-sec-authz-service
```

## API usage

### Authentication
Each request on URL path `/services/authz/pap` requires HTTP Basic authentication with test admin account: username `admin`, password `admin`.

### Create or Update the access policy for a given Kafka topic
Create/update the access policy of a given topic (if the policy does not exist, it is created on the fly), say topic `Topic_A` with the HTTP request below (only important headers shown for conciseness, e.g.Content-Length header is omitted but required as usual):
**Beware the Authorization header with value: `Basic xxx`, where `xxx` is the string (username:password) `admin:admin` encoded in base 64, according to HTTP Basic Authentication standard.**

```
Address: http://localhost:8080/services/authz/pap/policies/resource.type=TOPIC/policies;resource.id=Topic_A
Encoding: UTF-8
Http-Method: PUT
Content-Type: application/json
Headers: {Accept=[application/json], Authorization=[Basic YWRtaW46YWRtaW4=]}
Payload: {"rules":[{"subject":"clientID1","permissions":[{"allow":true,"action":"PUBLISH"},{"allow":false,"action":"SUBSCRIBE"}]},{"subject":"clientID2","permissions":[{"allow":true,"action":"SUBSCRIBE"}]}]}
```

The JSON object in the payload must be valid against the JSON schema in [src/main/resources/eu/driver/testbed/sec/authz/service/access_policy.schema.json](src/main/resources/eu/driver/testbed/sec/authz/service/access_policy.schema.json).

### Get the current access policy for a given Kafka topic
Get the access policy for topic `Topic_A` for instance with a HTTP request as follows (only important headers shown for conciseness, e.g.Content-Length header is omitted but required as usual):

```
Address: http://localhost:8080/services/authz/pap/policies/resource.type=TOPIC/policies;resource.id=Topic_A
Encoding: UTF-8
Http-Method: GET
Content-Type: 
Headers: {Accept=[application/json], Authorization=[Basic YWRtaW46YWRtaW4=]}
```

Example of response:

```
Response-Code: 200
Content-Type: application/json
Headers: {Content-Type=[application/json]}
Payload: {"rules":[{"subject":"clientID1","permissions":[{"allow":true,"action":"PUBLISH"},{"allow":false,"action":"SUBSCRIBE"}]},{"subject":"clientID2","permissions":[{"allow":true,"action":"SUBSCRIBE"}]}]}
```

### Delete the access policy for a given Kafka topic
E.g. for topic `Topic_A`


```
Address: http://localhost:8080/services/authz/pap/policies/resource.type=TOPIC/policies;resource.id=Topic_A
Encoding: UTF-8
Http-Method: DELETE
Content-Type: */*
Headers: {Accept=[application/json], Authorization=[Basic YWRtaW46YWRtaW4=]}
```

### HTTPS
It is possible to enable HTTPS by setting `server.ssl.enabled` to `true` in `docker/application.properties` file and `sec:http/sec:intercept-url/@requires-channel` attribute value to `https` in file `target/test-classes/spring-beans.xml`. Then stop/re-run the Docker as shown earlier.

### TODO
Use client certificate authentication

