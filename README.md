[![Build Status](https://travis-ci.org/DRIVER-EU/test-bed-security-authorization-service.svg?branch=master)](https://travis-ci.org/DRIVER-EU/test-bed-security-authorization-service)

# Test-bed Security Service for Authorization
REST service that provides access policy administration and evaluation to render a decision (Permit/Deny) for a given access request, aka *PAP* (Policy Access Point) and *PDP* (Policy Decision Point) in [XACML](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html) standard.

## System requirements
* OS: Linux x86_64
* Filesystem: ext4
* JRE: OpenJDK 8
* RAM: 2GB or more

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
$ docker run -p 8080:8080 -t drivereu/driver-testbed-sec-authz-service
```

You can customize the application's configuration (`application.yml` and `conf` folder) by mounting volumes (on `/application.yml` and ` and `/opt/driver-testbed-sec-authz-service/conf` respectively):

```sh
$ docker run -v docker/application.yml:/application.yml:ro -v target/test-classes:/opt/driver-testbed-sec-authz-service/conf:ro -p 8080:8080 -t drivereu/driver-testbed-sec-authz-service
```

You can enable SSL with `ssl` Spring profile and customize other application properties, either using a custom `application.yml` as shown above (with line `spring.profiles.active: ssl`), or with JVM arguments on the command line:

```sh
$ docker run -e JAVA_OPTS="-Dspring.profiles.active=ssl -Djava.security.egd=file:/dev/./urandom -Djava.awt.headless=true -Djavax.xml.accessExternalSchema=all -Xms1024m -Xmx2048m -XX:+UseConcMarkSweepGC -server" -p 8443:8443 -t drivereu/driver-testbed-sec-authz-service
```


## API usage

### Authentication
Each request on URL path `/services/authz/pap` requires HTTP Basic authentication with test admin account: username `admin`, password `admin`.

You can also enable SSL (with client certificate authentication) by modifying the file `application.yml` and setting the following properties:

```
spring.profiles.active=ssl
```

Once SSL is enabled, access to URL path `/services/authz/pap` requires authentication with a client certificate issued by the test CA (PKCS#12 keystore file is `ca.p12`) in the [test folder](src/test). In this case, this replaces HTTP Basic Authentication. You can use the example of client certificate [client.p12](src/test/resources) (PKCS#12 keystore file).


### Create or Update the access policy for a given Kafka topic
Create/update the access policy of a given topic (if the policy does not exist, it is created on the fly), say topic `Topic_A` with the HTTP request below (only important headers shown for conciseness, e.g.Content-Length header is omitted but required as usual):
If SSL is not enabled, **beware the Authorization header with value: `Basic xxx`, where `xxx` is the string (username:password) `admin:admin` encoded in base 64, according to HTTP Basic Authentication standard.**

Every HTTP payload sent to this API is a JSON object that must be valid against the JSON schema in [src/main/resources/eu/driver/testbed/sec/authz/service/access_policy.schema.json](src/main/resources/eu/driver/testbed/sec/authz/service/access_policy.schema.json).


#### Authorizing Kafka clients on a given topic

```
Address: http://localhost:8080/services/authz/pap/policies/resource.type=TOPIC/policies;resource.id=Topic_A
Encoding: UTF-8
Http-Method: PUT
Content-Type: application/json
Headers: {Accept=[application/json], content-type=[application/json], Authorization=[Basic YWRtaW46YWRtaW4=]}
Payload: {"rules":[{"subject.id":"client1","permissions":[{"allow":true,"action":"PUBLISH"},{"allow":false,"action":"SUBSCRIBE"},{"allow":false,"action":"DESCRIBE"}]},{"subject.id":"client2","permissions":[{"allow":true,"action":"SUBSCRIBE"},{"allow":false,"action":"DESCRIBE"}]}]}
```

This request grants publish/subscribe permissions to `client1` (publish only) and `client2` (subscribe only) on the topic `Topic_A`.

**The `subject.id` value must match the Kafka client ID, i.e. if SSL is enabled, the subject DN in the client certificate, e.g. `CN=client1,OU=Authz Service Dev Project,OU=WP923,O=DRIVER-PROJECT.eu`**

For a Kafka topic, actions `PUBLISH` (resp. `SUBSCRIBE`) and `WRITE` (resp. `READ`) are interchangeable in the request above.

#### Authorizing Kafka clients to join a given consumer group

```
Address: http://localhost:8080/services/authz/pap/policies/resource.type=GROUP/policies;resource.id=ConsumerGroup1
Encoding: UTF-8
Http-Method: PUT
Content-Type: application/json
Headers: {Accept=[application/json], content-type=[application/json], Authorization=[Basic YWRtaW46YWRtaW4=]}
Payload: {"rules":[{"subject.id":"client1","permissions":[{"allow":true,"action":"READ"},{"allow":true,"action":"DESCRIBE"}]}]}
```

This request allows `client1` to join the consumer group `ConsumerGroup1`.

#### Authorizing a Kafka consumer group on a given topic

```
Address: http://localhost:8080/services/authz/pap/policies/resource.type=TOPIC/policies;resource.id=TOPIC_A
Encoding: UTF-8
Http-Method: PUT
Content-Type: application/json
Headers: {Accept=[application/json], content-type=[application/json], Authorization=[Basic YWRtaW46YWRtaW4=]}
Payload: {"rules":[{"subject.group":"ConsumerGroup1","permissions":[{"allow":true,"action":"READ"},{"allow":true,"action":"DESCRIBE"}]}]}
```

This request allows (all clients in) the consumer group `ConsumerGroup1` to subscribe to the topic `Topic_A`.

### Get the current access policy for a given Kafka topic or group
Get the access policy for topic `Topic_A` for instance with a HTTP request as follows (only important headers shown for conciseness, e.g.Content-Length header is omitted but required as usual):

```
Address: http://localhost:8080/services/authz/pap/policies/resource.type=TOPIC/policies;resource.id=Topic_A
Encoding: UTF-8
Http-Method: GET
Content-Type: 
Headers: {Accept=[application/json], Authorization=[Basic YWRtaW46YWRtaW4=]}
```

To get a group access policy, replace `TOPIC` with `GROUP` (and `Topic_A` with the group ID) in the previous request.

Example of response:

```
Response-Code: 200
Content-Type: application/json
Headers: {Content-Type=[application/json]}
Payload: {"rules":[{"subject":"clientID1","permissions":[{"allow":true,"action":"PUBLISH"},{"allow":false,"action":"SUBSCRIBE"},{"allow":false,"action":"DESCRIBE"}]},{"subject":"client2","permissions":[{"allow":true,"action":"SUBSCRIBE"},{"allow":false,"action":"DESCRIBE"}]}]}
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

To delete a group access policy, replace `TOPIC` with `GROUP` (and `Topic_A` with the group ID) in the previous request.
