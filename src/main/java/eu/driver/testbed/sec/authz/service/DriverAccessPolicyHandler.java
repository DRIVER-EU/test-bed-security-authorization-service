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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateExceptionHandler;

/**
 * Driver-to-XACML JSON Policy conversion utilities
 *
 */
public final class DriverAccessPolicyHandler
{
	/**
	 * Access rule in a DRIVER access policy
	 */
	public static final class DriverAccessRule
	{
		private static final List<String> SUBJECT_MATCH_ATT_IDENTIFIERS = Arrays.asList("subject.id", "subject.group");

		/**
		 * Subject attributes to be matched for the rule to apply
		 */
		private final Map<String, Object> subjectMatches = Maps.newHashMapWithExpectedSize(SUBJECT_MATCH_ATT_IDENTIFIERS.size());

		/**
		 * Permitted actions
		 */
		private final List<Object> permissions;

		private DriverAccessRule(final JSONObject schemaValidJsonRuleJsonObject)
		{
			SUBJECT_MATCH_ATT_IDENTIFIERS.forEach(attId -> {
				final String matchedVal = schemaValidJsonRuleJsonObject.optString(attId);
				if (!matchedVal.isEmpty())
				{
					subjectMatches.put(attId, matchedVal);
				}
			});

			permissions = schemaValidJsonRuleJsonObject.getJSONArray("permissions").toList();
		}

		/**
		 * @return Subject attributes to be matched for the rule to apply
		 */
		public Map<String, Object> getSubjectMatches()
		{
			return subjectMatches;
		}

		/**
		 * @return Permitted actions
		 */
		public List<Object> getPermissions()
		{
			return permissions;
		}

	}

	/**
	 * Loads schema from Spring-handled resource
	 * 
	 * @param schemaLocation
	 *            schema location (Spring URL)
	 * @return JSON schema instance
	 * @throws IOException
	 *             error loading the schema
	 */
	public static Schema newJsonSchema(final Resource schemaLocation) throws IOException
	{
		Preconditions.checkArgument(schemaLocation != null, "Undefined location of JSON schema");

		try (final Reader reader = new BufferedReader(new InputStreamReader(schemaLocation.getInputStream(), StandardCharsets.UTF_8)))
		{
			final JSONObject rawSchema = new JSONObject(new JSONTokener(reader));
			// final SchemaLoader schemaLoader = schemaLoaderBuilder.schemaJson(rawSchema).build();
			return SchemaLoader.load(rawSchema); // schemaLoader.load().build();
		}

	}

	private static final Logger LOGGER = LoggerFactory.getLogger(DriverAccessPolicyHandler.class);

	private final Template driverToXacmlJsonPolicyFtl;

	/**
	 * Creates an instance with an optional location to a customized transformation template (FreeMarker)
	 * 
	 * @param driverAccessPolicyJsonSchema
	 *            DRIVER's access policy schema
	 * 
	 * @param driverToXacmlJsonPolicyFtlLocation
	 *            Spring-ResourceLoader-compatible location of a transformation template (FreeMarker)
	 */
	public DriverAccessPolicyHandler(final Schema driverAccessPolicyJsonSchema, final String driverToXacmlJsonPolicyFtlLocation)
	{
		Preconditions.checkArgument(driverAccessPolicyJsonSchema != null, "Undefined DRIVER's access policy JSON schema");

		// Create your Configuration instance, and specify if up to what FreeMarker
		// version (here 2.3.27) do you want to apply the fixes that are not 100%
		// backward-compatible. See the Configuration JavaDoc for details.
		final Configuration xacmlReqTmplEngineCfg = new Configuration(Configuration.VERSION_2_3_23);

		// Sets how errors will appear.
		// During web page *development* TemplateExceptionHandler.HTML_DEBUG_HANDLER is
		// better.
		xacmlReqTmplEngineCfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);

		// Don't log exceptions inside FreeMarker that it will thrown at you anyway:
		// XACML_REQ_TMPL_ENGINE_CFG.setLogTemplateExceptions(false);

		// Wrap unchecked exceptions thrown during template processing into
		// TemplateException-s.
		// FREEMARKER_CFG.setWrapUncheckedExceptions(true);

		xacmlReqTmplEngineCfg.setTemplateLoader(new SpringUrlTemplateLoader());
		xacmlReqTmplEngineCfg.setLocalizedLookup(false);

		try
		{
			driverToXacmlJsonPolicyFtl = xacmlReqTmplEngineCfg.getTemplate(driverToXacmlJsonPolicyFtlLocation, StandardCharsets.UTF_8.displayName());
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
	 *            Driver access policy assumed valid.
	 * @param policyId
	 *            policyId set in the resulting XACML/JSON policy
	 * @param policyVersion
	 *            policy Version set in the resulting XACML/JSON policy
	 * @param targetValue
	 *            policy's Match/AttributeValue set in the resulting XACML/JSON policy's Target (Target contains a single Match)
	 * @return XACML/JSON policy
	 */
	public JSONObject toXacmlJsonPolicy(final JSONObject schemaValidDriverAccessPolicy, final String policyId, final String policyVersion, final String targetValue)
	{
		/*
		 * driverAccessPolicy assumed valid against JSON schema
		 */

		/*
		 * { "rules": [ { "subject": "clientID1", "permissions": [ { "action": "PUBLISH", "allow": true }, { "action": "SUBSCRIBE", "allow": false } ] }, { "subject": "clientID2", "permissions": [ {
		 * "action": "SUBSCRIBE", "allow": true } ] } ] }
		 */
		final JSONArray jsonRules = schemaValidDriverAccessPolicy.getJSONArray("rules");
		final List<DriverAccessRule> driverAccessRules = new ArrayList<>(jsonRules.length());
		for (final Object jsonRule : jsonRules)
		{
			if (jsonRule instanceof JSONObject)
			{
				final DriverAccessRule accessRule = new DriverAccessRule((JSONObject) jsonRule);
				driverAccessRules.add(accessRule);
			}
		}

		final Map<String, Object> root = ImmutableMap.of("id", policyId, "version", policyVersion, "targetValue", targetValue, "driverAccessRules", driverAccessRules);
		final StringWriter out = new StringWriter();
		LOGGER.debug("Generating XACML/JSON policy from DRIVER access rules using template with input: {}", root);
		try
		{
			driverToXacmlJsonPolicyFtl.process(root, out);
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