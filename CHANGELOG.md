# Change log
All notable changes to this project are documented in this file following the [Keep a CHANGELOG](http://keepachangelog.com) conventions.


## 2.1.1
### Changed
- Externalized configuration of DRIVER's access policy schema (JSON)

### Fixed
- XACML/JSON-XACML/XML Match element conversion: the AttributeValue datatype was always the same as the AttributeDesignator/Selector's whereas it must be different for certain functions like x500Name-regexp-match


## 2.0.0
### Changed
- REST API: `subject` key replaced with `subject.id` in JSON payload of access policy, to avoid confusion with new subject attributes (e.g. `subject.group`). Also `subject.id` is optional.
- Dockerfile: allow custom JAVA_OPTS at runtime (environment variable) and separation of static config folder from variable data folder inside the container
- Copyright company name
- Upgraded maven parent project version to 7.5.0
- Upgraded dependency versions: 
	- authzforce-ce-restful-pdp-jaxrs: 1.6.0
	- freemarker: 2.3.28
- Indirectly changed dependency versions:
	- authzforce-ce-jaxrs-utils version: 1.3.0
	- authzforce-ce-core* version: 13.3.0
	- authzforce-ce-core-pdp-api: 15.3.0
	- authzforce-ce-xacml-json-model: 2.1.0
	- Spring: 4.3.18 (fixes CVE)
	- Guava: 24.1.1-jre
  	- jaxb2-basics: 1.11.1
  	- mailapi replaced with javax.mail-api: 1.6.0

### Added
- #4 : REST API enhancements: 
	- New `subject.group` key in JSON payload of access policy; allows group-based permissions, i.e. to grant permission to a Kafka consumer group (instead of specific Kafka clients). See [README](README.md) for more information.
	- If neither `subject.id` or `subject.group` is specified, the permissions apply to any subject (wildcard).
- In PDP configuration (pdp.xml), 'policyLocation' elements now support system properties and environment variables (enclosed between '${...}') with default value (separated from property name by '!') if the property/variable is undefined. More generally, PDP extensions such as Attribute and Policy Providers can now accept placeholders for system properties and environment variables in their string configuration parameters (as part of PDP configuration) and perform placeholder replacements with their factory method's input EnvironmentProperties.


## 1.2.0
### Added
- Possibility to override/customize by configuration the Freemarker template for Driver+-to-XACML-access-policy transformation (in Spring config file defined by application property 'spring.beans.conf', bean class 'AuthzWsJaxrsRootResource' has new constructor arg 'driverToXacmlJsonPolicyFtlLocation')


## 1.1.0
### Changed
- Maven project's parent version: 7.4.0 
	-> Upgrade Apache CXF version (to fix a CVE): 3.2.5
- Maven dependency versions:
	- Spring Framework: 4.3.18 (fix CVE-2018-8014)
	- authzforce-ce-restful-pdp-jaxrs: 1.5.0 (fix CVE-2018-1304, CVE-2018-1305)
		- authzforce-ce-core: 13.2.0
- Docker image based on jre instead of jdk
	
### Fixed
- #1: Windows compatibility
	
### Added
- SSL support with client certificate authentication
- Unit tests with and without SSL (with client certificate authentication on /pap)
- #2: Automated build with Travis CI
	- Automated Maven artifact deployment DRIVER-EU github repository
	- Automated docker image deployment to drivereu organization on Docker Hub


## 1.0.0
Initial release
