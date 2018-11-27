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
package eu.driver.testbed.sec.authz.service.test;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.ws.rs.NotFoundException;

import org.apache.cxf.jaxrs.client.WebClient;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ow2.authzforce.jaxrs.util.JsonRiJaxrsProvider;
import org.ow2.authzforce.xacml.json.model.LimitsCheckingJSONObject;
import org.ow2.authzforce.xacml.json.model.XacmlJsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.FileSystemUtils;

import eu.driver.testbed.sec.authz.service.AuthzWsSpringBootApp;
import eu.driver.testbed.sec.authz.service.DriverAccessPolicyHandler;

/**
 * Test for CXF/JAX-RS-based REST profile implementation using XACML JSON Profile for payloads
 * 
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = AuthzWsSpringBootApp.class, webEnvironment = WebEnvironment.RANDOM_PORT)
public class AuthzWsSpringBootAppTest
{
	private static final Logger LOGGER = LoggerFactory.getLogger(AuthzWsSpringBootApp.class);

	private static final int MAX_JSON_STRING_LENGTH = 100;

	/*
	 * Max number of child elements - key-value pairs or items - in JSONObject/JSONArray
	 */
	private static final int MAX_JSON_CHILDREN_COUNT = 100;

	private static final int MAX_JSON_DEPTH = 100;

	/*
	 * If port > 0, enable testing of an external server running on this port
	 */
	private static final int EXTERNAL_SERVER_PORT = Integer.parseInt(System.getProperty("eu.driver.testbed.sec.authz.service.test.ext.port", "-1"), 10);

	@BeforeClass
	public static void setup() throws IOException
	{
		System.setProperty("javax.xml.accessExternalSchema", "http,file");
		/*
		 * Clean policies directory for testing (delete/recreate)
		 */
		final Path targetPrp = Paths.get("target/test-classes/policies");
		if (Files.exists(targetPrp))
		{
			try (final Stream<Path> fileStream = Files.walk(targetPrp))
			{
				fileStream.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
			}
		}

		final Path srcPrp = Paths.get("src/test/resources/policies");
		FileSystemUtils.copyRecursively(srcPrp.toFile(), targetPrp.toFile());
	}

	@LocalServerPort
	private int localPort;

	@Value("${server.ssl.enabled}")
	private boolean tlsEnabled;

	private WebClient papClient = null;
	private WebClient pdpClient = null;

	/*
	 * You cannot use Spring-injected variables in the constructor like this because it is called before the Spring ApplicationContext is loaded
	 */
	// public AuthzWsSpringBootAppTest()
	// {
	/*
	 * This will fail (port not yet set by Spring so set to default value 0 at this point)
	 */
	// System.out.println("server.port: " + port);
	// }

	// @Autowired
	// private TestRestTemplate restTemplate;

	@Before
	public void setupTest()
	{
		final String scheme = tlsEnabled ? "https" : "http";
		final int port = EXTERNAL_SERVER_PORT > 0 ? EXTERNAL_SERVER_PORT : localPort;
		final String baseAddress = scheme + "://localhost:" + port + "/services";

		final List<Object> providers = Collections.singletonList(new JsonRiJaxrsProvider());
		papClient = WebClient.create(baseAddress, providers, "classpath:cxf-http-client.xml").path("authz").path("pap");
		pdpClient = WebClient.create(baseAddress, providers, "classpath:cxf-http-client.xml").path("authz").path("pdp");

		/*
		 * If TLS enabled, client certificate will be required when ssl profile enabled, else HTTP Basic
		 */
		LOGGER.debug("Client baseAdress: {}", baseAddress);

		if (!tlsEnabled)
		{
			/*
			 * HTTP Basic authentication
			 */
			final String authorizationHeader = "Basic " + org.apache.cxf.common.util.Base64Utility.encode("admin:admin".getBytes());
			papClient.header("Authorization", authorizationHeader);
		}
	}

	// @Test
	// public void testPolicyConversion() throws IOException
	// {
	// TODO: test validation of DRIVER-formatted policy and conversion to AuthzForce-XACML/JSON format
	// }

	private JSONObject getTopLevelPolicy(final String policyId)
	{
		return WebClient.fromClient(this.papClient, true).path("policies").path(policyId).accept("application/json").get(JSONObject.class);
	}

	private JSONObject setChildPolicy(final String parentPolicyId, final String childPolicyTargetMatchAttributeId, final String childPolicyTargetMatchAttributeValue,
	        final JSONObject childPolicyContent)
	{
		return WebClient.fromClient(this.papClient, true).path("policies").path(parentPolicyId).path("policies").matrix(childPolicyTargetMatchAttributeId, childPolicyTargetMatchAttributeValue)
		        .type("application/json").accept("application/json").put(childPolicyContent, JSONObject.class);
	}

	private JSONObject getChildPolicy(final String parentPolicyId, final String childPolicyTargetMatchAttributeId, final String childPolicyTargetMatchAttributeValue)
	{
		return WebClient.fromClient(this.papClient, true).path("policies").path(parentPolicyId).path("policies").matrix(childPolicyTargetMatchAttributeId, childPolicyTargetMatchAttributeValue)
		        .accept("application/json").get(JSONObject.class);
	}

	private void deleteChildPolicy(final String parentPolicyId, final String childPolicyTargetMatchAttributeId, final String childPolicyTargetMatchAttributeValue)
	{
		WebClient.fromClient(this.papClient, true).path("policies").path(parentPolicyId).path("policies").matrix(childPolicyTargetMatchAttributeId, childPolicyTargetMatchAttributeValue).delete();

	}

	private boolean verifyChildPolicyRef(final String parentPolicyId, final String childPolicyId)
	{
		final JSONObject parentPolicy = getTopLevelPolicy(parentPolicyId);
		return StreamSupport.stream(parentPolicy.getJSONObject("policy").getJSONArray("policies").spliterator(), true).anyMatch(json -> {
			if (json instanceof JSONObject)
			{
				/*
				 * Check whether it is the right child policy reference
				 */
				final JSONObject policyRefJsonObject = ((JSONObject) json).optJSONObject("policyRef");
				return policyRefJsonObject != null && policyRefJsonObject.getString("id").equals(childPolicyId);
			}
			return false;
		});
	}

	@Test
	public void getTopLevelPolicy() throws IOException
	{
		final JSONObject actualResponse = getTopLevelPolicy("root");
		final JSONObject policyJO = actualResponse.getJSONObject("policy");
		Assert.assertNotNull("No root key 'policy' with JSONObject value", policyJO);
		XacmlJsonUtils.POLICY_SCHEMA.validate(policyJO);

		Assert.assertEquals("Invalid returned policy Id", policyJO.getString("id"), "root");

		final JSONObject actualResponse2 = getTopLevelPolicy("resource.type=TOPIC");
		final JSONObject policyJO2 = actualResponse2.getJSONObject("policy");
		XacmlJsonUtils.POLICY_SCHEMA.validate(policyJO2);

		Assert.assertEquals("Invalid returned policy Id", policyJO2.getString("id"), "resource.type=TOPIC");
	}

	@Test
	public void setAndDeleteChildPolicy() throws IOException
	{
		final Path path = Paths.get("src/test/resources/samples/pap/topicX-access-policy.driver.json");
		final String jsonStr = new String(Files.readAllBytes(path));
		final JSONObject schemaValidDriverAccessPolicy = new JSONObject(jsonStr);
		DriverAccessPolicyHandler.DRIVER_ACCESS_POLICY_JSON_SCHEMA.validate(schemaValidDriverAccessPolicy);

		final JSONObject actualResponse = setChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_A", schemaValidDriverAccessPolicy);
		Assert.assertTrue("Invalid returned policy content (policy in response != policy in request)", actualResponse.similar(schemaValidDriverAccessPolicy));

		/*
		 * Make sure the new child policy is there
		 */
		final JSONObject actualChildPolicyContent = getChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_A");
		Assert.assertTrue("Invalid returned policy content", actualChildPolicyContent.similar(schemaValidDriverAccessPolicy));

		/*
		 * Make sure the reference is added to the parent policy
		 */
		final boolean childPolicyRefFound = verifyChildPolicyRef("resource.type=TOPIC", "resource.type=TOPIC#resource.id=TOPIC_A");
		Assert.assertTrue("Child policy reference not found in parent policy", childPolicyRefFound);

		/*
		 * Update again
		 */
		final Path path2 = Paths.get("src/test/resources/samples/pap/topicX-access-policy2.driver.json");
		final String jsonStr2 = new String(Files.readAllBytes(path2));
		final JSONObject schemaValidDriverAccessPolicy2 = new JSONObject(jsonStr2);
		DriverAccessPolicyHandler.DRIVER_ACCESS_POLICY_JSON_SCHEMA.validate(schemaValidDriverAccessPolicy);
		final JSONObject actualResponse2 = setChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_A", schemaValidDriverAccessPolicy2);
		Assert.assertTrue("Invalid returned policy content (policy in response != policy in request)", actualResponse2.similar(schemaValidDriverAccessPolicy2));

		/*
		 * Make sure the update is there
		 */
		final JSONObject actualChildPolicyContent2 = getChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_A");
		Assert.assertTrue("Invalid returned policy content", actualChildPolicyContent2.similar(schemaValidDriverAccessPolicy2));
		final boolean childPolicyRefFound2 = verifyChildPolicyRef("resource.type=TOPIC", "resource.type=TOPIC#resource.id=TOPIC_A");
		Assert.assertTrue("Child policy reference not found in parent policy", childPolicyRefFound2);

		/*
		 * Add another child policy
		 */
		setChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_B", schemaValidDriverAccessPolicy);
		final JSONObject actualChildPolicyContent3 = getChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_B");
		Assert.assertTrue("Invalid returned policy content", actualChildPolicyContent3.similar(schemaValidDriverAccessPolicy));
		final boolean childPolicyRefFound3 = verifyChildPolicyRef("resource.type=TOPIC", "resource.type=TOPIC#resource.id=TOPIC_B");
		Assert.assertTrue("Child policy reference not found in parent policy", childPolicyRefFound3);

		/*
		 * Undo: remove child policy
		 */
		deleteChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_A");
		try
		{
			getChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_A");
			Assert.fail("Child policy still exists");
		}
		catch (final NotFoundException e)
		{
			// OK
		}

		final boolean childPolicyRefFound4 = verifyChildPolicyRef("resource.type=TOPIC", "resource.type=TOPIC#resource.id=TOPIC_A");
		Assert.assertTrue("Child policy reference still in parent policy after DELETE operation", !childPolicyRefFound4);

		final boolean childPolicyRefFound5 = verifyChildPolicyRef("resource.type=TOPIC", "resource.type=TOPIC#resource.id=TOPIC_B");
		Assert.assertTrue("Wrong child policy reference removed from parent policy after DELETE operation on other child policy", childPolicyRefFound5);

		deleteChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_B");
		try
		{
			getChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_B");
			Assert.fail("Child policy still exists");
		}
		catch (final NotFoundException e)
		{
			// OK
		}

		final boolean childPolicyRefFound6 = verifyChildPolicyRef("resource.type=TOPIC", "resource.type=TOPIC#resource.id=TOPIC_B");
		Assert.assertTrue("Child policy reference still in parent policy after DELETE operation", !childPolicyRefFound6);
	}

	/*
	 * Policy with action different from special cases SUBSCRIBE/PUBLISH
	 */
	@Test
	public void setChildPolicyWithOtherAction() throws IOException
	{
		final Path path = Paths.get("src/test/resources/samples/pap/topicX-access-policy3.driver.json");
		final String jsonStr = new String(Files.readAllBytes(path));
		final JSONObject schemaValidDriverAccessPolicy = new JSONObject(jsonStr);
		DriverAccessPolicyHandler.DRIVER_ACCESS_POLICY_JSON_SCHEMA.validate(schemaValidDriverAccessPolicy);

		final JSONObject actualResponse = setChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_C", schemaValidDriverAccessPolicy);
		Assert.assertTrue("Invalid returned policy content (policy in response != policy in request)", actualResponse.similar(schemaValidDriverAccessPolicy));

		/*
		 * Make sure the new child policy is there
		 */
		final JSONObject actualChildPolicyContent = getChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_C");
		Assert.assertTrue("Invalid returned policy content", actualChildPolicyContent.similar(schemaValidDriverAccessPolicy));

		/*
		 * Make sure the reference is added to the parent policy
		 */
		final boolean childPolicyRefFound = verifyChildPolicyRef("resource.type=TOPIC", "resource.type=TOPIC#resource.id=TOPIC_C");
		Assert.assertTrue("Child policy reference not found in parent policy", childPolicyRefFound);

		/*
		 * Undo: remove child policy
		 */
		deleteChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_C");
		try
		{
			getChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_C");
			Assert.fail("Child policy still exists");
		}
		catch (final NotFoundException e)
		{
			// OK
		}
	}

	@Test
	public void testPdpRequest() throws IOException
	{
		/*
		 * Set the policy
		 */
		final Path path = Paths.get("src/test/resources/samples/pap/topicX-access-policy.driver.json");
		final String jsonStr = new String(Files.readAllBytes(path));
		final JSONObject schemaValidDriverAccessPolicy = new JSONObject(jsonStr);
		setChildPolicy("resource.type=TOPIC", "resource.id", "TOPIC_A", schemaValidDriverAccessPolicy);

		// Request body
		try (final DirectoryStream<Path> dirStream = Files.newDirectoryStream(Paths.get("src/test/resources/samples/pdp")))
		{
			dirStream.forEach(dir -> {
				if (Files.isDirectory(dir))
				{
					try
					{
						testPdpRequest(dir);
					}
					catch (final IOException e)
					{
						throw new RuntimeException(e);
					}
				}
			});
		}
	}

	private void testPdpRequest(final Path pdpDeniedRequestsDir) throws IOException
	{
		final Path reqLocation = pdpDeniedRequestsDir.resolve("Request.xacml.json");
		try (final Reader reqIn = Files.newBufferedReader(reqLocation))
		{
			final JSONObject jsonRequest = new LimitsCheckingJSONObject(reqIn, MAX_JSON_STRING_LENGTH, MAX_JSON_CHILDREN_COUNT, MAX_JSON_DEPTH);
			if (!jsonRequest.has("Request"))
			{
				throw new IllegalArgumentException("Invalid XACML JSON Request file: " + reqLocation + ". Expected root key: \"Request\"");
			}

			XacmlJsonUtils.REQUEST_SCHEMA.validate(jsonRequest);

			// expected response
			final Path respLocation = pdpDeniedRequestsDir.resolve("Response.xacml.json");
			try (final Reader respIn = Files.newBufferedReader(respLocation))
			{
				final JSONObject expectedResponse = new LimitsCheckingJSONObject(respIn, MAX_JSON_STRING_LENGTH, MAX_JSON_CHILDREN_COUNT, MAX_JSON_DEPTH);
				if (!expectedResponse.has("Response"))
				{
					throw new IllegalArgumentException("Invalid XACML JSON Response file: " + respLocation + ". Expected root key: \"Response\"");
				}

				XacmlJsonUtils.RESPONSE_SCHEMA.validate(expectedResponse);

				// send request
				final WebClient client = WebClient.fromClient(this.pdpClient, true);
				final JSONObject actualResponse = client.type("application/json").accept("application/json").post(jsonRequest, JSONObject.class);

				// check response
				Assert.assertTrue(expectedResponse.similar(actualResponse));
			}
		}
	}

	// public static void main(String... args) throws FileNotFoundException
	// {
	// final String reqLocation = "src/test/resources/Request.json";
	// final InputStream reqIn = new FileInputStream(reqLocation);
	// final JSONObject jsonRequest = new LimitsCheckingJSONObject(reqIn, MAX_JSON_STRING_LENGTH, MAX_JSON_CHILDREN_COUNT, MAX_JSON_DEPTH);
	// final JSONObject catObj = jsonRequest.getJSONObject("Request").getJSONArray("Category").getJSONObject(0);
	// Xacml3JsonUtils.REQUEST_SCHEMA.validate(catObj);
	// }
}
