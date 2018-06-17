/**
 * Copyright (C) 2012-2018 Thales Services SAS.
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;

import freemarker.cache.ClassTemplateLoader;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateExceptionHandler;

/**
 * Driver-to-XACML JSON Policy conversion utilities
 *
 */
public final class DriverAccessPolicyUtils
{
	private static final Logger LOGGER = LoggerFactory.getLogger(DriverAccessPolicyUtils.class);

	/**
	 * JSON schema for validating Driver+/JSON access policies (see driver-access-policy.schema), to be used by external libraries (like CXF JSON provider)
	 */
	public static final Schema JSON_SCHEMA;

	static
	{
		try (final Reader reader = new BufferedReader(new InputStreamReader(DriverAccessPolicyUtils.class.getResourceAsStream("access_policy.schema.json"), StandardCharsets.UTF_8)))
		{
			final JSONObject rawSchema = new JSONObject(new JSONTokener(reader));
			// final SchemaLoader schemaLoader = schemaLoaderBuilder.schemaJson(rawSchema).build();
			JSON_SCHEMA = SchemaLoader.load(rawSchema); // schemaLoader.load().build();
		}
		catch (final IOException e)
		{
			throw new RuntimeException(e);
		}

	}

	private static final String DRIVER_TO_XACML_JSON_POLICY_TMPL_FILENAME = "driver-to-xacml-json.ftl";

	private static final Template DRIVER_TO_XACML_JSON_POLICY_TMPL;

	static
	{
		// Create your Configuration instance, and specify if up to what FreeMarker
		// version (here 2.3.27) do you want to apply the fixes that are not 100%
		// backward-compatible. See the Configuration JavaDoc for details.
		final Configuration xacmlReqTmplEngineCfg = new Configuration(Configuration.VERSION_2_3_23);
		// Set the preferred charset template files are stored in. UTF-8 is
		// a good choice in most applications:
		xacmlReqTmplEngineCfg.setDefaultEncoding("UTF-8");

		// Sets how errors will appear.
		// During web page *development* TemplateExceptionHandler.HTML_DEBUG_HANDLER is
		// better.
		xacmlReqTmplEngineCfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);

		// Don't log exceptions inside FreeMarker that it will thrown at you anyway:
		// XACML_REQ_TMPL_ENGINE_CFG.setLogTemplateExceptions(false);

		// Wrap unchecked exceptions thrown during template processing into
		// TemplateException-s.
		// FREEMARKER_CFG.setWrapUncheckedExceptions(true);

		final ClassTemplateLoader tmplLoader = new ClassTemplateLoader(DriverAccessPolicyUtils.class, "");
		xacmlReqTmplEngineCfg.setTemplateLoader(tmplLoader);

		try
		{
			DRIVER_TO_XACML_JSON_POLICY_TMPL = xacmlReqTmplEngineCfg.getTemplate(DRIVER_TO_XACML_JSON_POLICY_TMPL_FILENAME);
		}
		catch (final IOException e)
		{
			throw new RuntimeException("Error getting template for Driver-to-XACML JSON policy transformation", e);
		}
	}

	/**
	 * Convert Driver access policy format to XACML/JSON format
	 * 
	 * @param schemaValidDriverAccessPolicy
	 *            Driver acess policy assumed valid against {@link #JSON_SCHEMA}.
	 * @param policyId
	 *            policyId set in the resulting XACML/JSON policy
	 * @param policyVersion
	 *            policy Version set in the resulting XACML/JSON policy
	 * @param targetValue
	 *            policy's Match/AttributeValue set in the resulting XACML/JSON policy's Target (Target contains a single Match)
	 * @return XACML/JSON policy
	 */
	public static JSONObject toXacmlJsonPolicy(final JSONObject schemaValidDriverAccessPolicy, final String policyId, final String policyVersion, final String targetValue)
	{
		/*
		 * driverAccessPolicy assumed valid against JSON schema
		 */

		/*
		 * { "rules": [ { "subject": "clientID1", "permissions": [ { "action": "PUBLISH", "allow": true }, { "action": "SUBSCRIBE", "allow": false } ] }, { "subject": "clientID2", "permissions": [ {
		 * "action": "SUBSCRIBE", "allow": true } ] } ] }
		 */

		final Map<String, Object> root = ImmutableMap.of("id", policyId, "version", policyVersion, "targetValue", targetValue, "driverAcrs",
		        schemaValidDriverAccessPolicy.getJSONArray("rules").toList());
		final StringWriter out = new StringWriter();
		LOGGER.debug("Generating XACML/JSON policy from DRIVER access rules using template with input: {}", root);
		try
		{
			DRIVER_TO_XACML_JSON_POLICY_TMPL.process(root, out);
		}
		catch (final Exception e)
		{
			throw new RuntimeException("Error generating XACML/JSON policy from DRIVER access rules", e);
		}

		final String xacmlJsonPolicy = out.toString();
		LOGGER.debug("Output from template: {}", xacmlJsonPolicy);

		/*
		 * Create final policy
		 */
		return new JSONObject(xacmlJsonPolicy);
	}

	// public static void main(final String... args) throws IOException
	// {
	// final Path path = Paths.get("src/test/resources/samples/topicX-access-policy.driver.json");
	// final String jsonStr = new String(Files.readAllBytes(path));
	// final JSONObject schemaValidDriverAccessPolicy = new JSONObject(jsonStr);
	// JSON_SCHEMA.validate(schemaValidDriverAccessPolicy);
	//
	// final JSONObject jo = DriverAccessPolicyUtils.toXacmlJsonPolicy(schemaValidDriverAccessPolicy, "resource-type=TOPIC#resource-id=TOPIC_A", "1.0", "TOPIC_A");
	// XacmlJsonUtils.POLICY_SCHEMA.validate(jo);
	// }
}