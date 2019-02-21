/**
 * Copyright (C) 2018-2019 THALES.
 *
 * This file is part of AuthzForce CE.
 *
 * AuthzForce CE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * AuthzForce CE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with AuthzForce CE.  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.driver.testbed.sec.authz.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * Spring Boot application's main class
 *
 */
// @Configuration
@EnableAutoConfiguration
@EnableWebSecurity
// @PropertySource("classpath:application.properties")
@ImportResource("${spring.beans.conf}")
public class AuthzWsSpringBootApp
{
	/**
	 * Main entry point
	 * 
	 * @param args
	 *            command-line arguments
	 */
	public static void main(final String[] args)
	{
		/*
		 * Allow use of http:// and file:// schema locations in XML catalogs for AuthzForce schemas
		 */
		System.setProperty("javax.xml.accessExternalSchema", "http,file");

		SpringApplication.run(AuthzWsSpringBootApp.class, args);
	}
}
