# Change log
All notable changes to this project are documented in this file following the [Keep a CHANGELOG](http://keepachangelog.com) conventions.


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