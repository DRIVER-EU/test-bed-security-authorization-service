/**
 * Copyright (C) 2012-2019 THALES.
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Paths;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.PathSegment;
import javax.xml.bind.JAXBException;
import javax.xml.transform.stream.StreamSource;

import org.everit.json.schema.Schema;
import org.json.JSONArray;
import org.json.JSONObject;
import org.ow2.authzforce.core.pdp.api.EnvironmentPropertyName;
import org.ow2.authzforce.core.pdp.api.policy.PolicyVersion;
import org.ow2.authzforce.core.pdp.impl.DefaultEnvironmentProperties;
import org.ow2.authzforce.core.pdp.impl.PdpEngineConfiguration;
import org.ow2.authzforce.core.pdp.impl.PdpModelHandler;
import org.ow2.authzforce.core.xmlns.pdp.Pdp;
import org.ow2.authzforce.core.xmlns.pdp.StaticRefPolicyProvider;
import org.ow2.authzforce.rest.pdp.jaxrs.XacmlPdpResource;
import org.ow2.authzforce.xacml.json.model.XacmlJsonUtils;
import org.ow2.authzforce.xmlns.pdp.ext.AbstractPolicyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.util.ResourceUtils;

import com.google.common.base.Preconditions;
import com.google.common.collect.Iterators;

/**
 * Root resource for the PAP
 */
@Path("authz")
public class AuthzWsJaxrsRootResource
{
	private static final Logger LOGGER = LoggerFactory.getLogger(AuthzWsJaxrsRootResource.class);

	private static final String DRIVER_ACCESS_POLICY_CONTENT_TYPE_ID = "driver.json";
	private static final String DEFAULT_POLICY_VERSION = "1.0";

	// private static final JSONObject convertJaxbAttributeDesignatorToJson(final AttributeDesignatorType jaxbAttributeDesignator/* , final Map<String, String> equalFunctionsByDatatype */)
	// {
	// assert jaxbAttributeDesignator != null/* && equalFunctionsByDatatype != null && !equalFunctionsByDatatype.isEmpty() */;
	// final String datatype = jaxbAttributeDesignator.getDataType();
	// // final String equalFuncId = equalFunctionsByDatatype.get(datatype);
	// // if (equalFuncId == null)
	// // {
	// // throw new RuntimeException(
	// // "Invalid 'equalFunctionsByDatatype' configuration parameter: no *-equal function defined for datatype '" + datatype + "' used in AttributeDesignator = " + jaxbAttributeDesignator);
	// // }
	//
	// /*
	// * Issuer may be null, in which case the JSONObject constructor skips the key-value pair, so it is as if there was not Issuer
	// */
	// return new JSONObject(ImmutableMap.of("category", jaxbAttributeDesignator.getCategory(), "issuer", jaxbAttributeDesignator.getIssuer(), "id", jaxbAttributeDesignator.getAttributeId(),
	// "dataType", datatype, "mustBePresent", jaxbAttributeDesignator.isMustBePresent()));
	// }

	// private static final int MAX_JSON_STRING_LENGTH = 65536;

	/*
	 * Max number of child elements - key-value pairs or items - in JSONObject/JSONArray
	 */
	// private static final int MAX_JSON_CHILDREN_COUNT = 50000;

	// private static final int MAX_JSON_DEPTH = 100;

	private static String incrementPolicyVersion(final String policyVersion)
	{
		assert policyVersion != null;
		final List<Integer> latestVersionInts = new PolicyVersion(policyVersion).getNumberSequence();
		final List<Integer> nextVersionInts = new ArrayList<>(latestVersionInts);
		nextVersionInts.set(nextVersionInts.size() - 1, latestVersionInts.get(latestVersionInts.size() - 1) + 1);
		return nextVersionInts.stream().map(i -> i.toString()).collect(Collectors.joining("."));
	}

	// private static JSONArray newXacmlJsonTargetValue(final String matchFunctionId, final String matchedValue, final JSONObject matchingXacmlAttributeDesignator)
	// {
	// assert matchFunctionId != null && matchedValue != null && matchingXacmlAttributeDesignator != null;
	//
	// final JSONObject match = new JSONObject(ImmutableMap.of("matchFunction", matchFunctionId, "value", matchedValue, "attributeDesignator", matchingXacmlAttributeDesignator));
	// /*
	// * Create the AllOf as an array of Match(es)
	// */
	// final JSONArray allOf = new JSONArray(Collections.singleton(match));
	//
	// /*
	// * Create the AnyOf as an array of AllOf(s) (single)
	// */
	// final JSONArray anyOf = new JSONArray(Collections.singleton(allOf));
	//
	// /*
	// * Create the Target as an array of AnyOf(s) (single)
	// */
	// return new JSONArray(Collections.singleton(anyOf));
	// }

	// private final Map<String, JSONObject> jsonAttributeDesignatorsByAlias;
	private final Pdp pdpJaxbConf;
	private final DefaultEnvironmentProperties pdpEnvProps;
	private final PrpDao prpDao;
	private final DriverAccessPolicyHandler driverAccessPolicyHandler;

	// private final Map<String, String> equalFunctionsByDatatype;
	// private final DriverToXacmlJsonPolicyConverter driverToXacmlJsonPolicyConverter;
	private transient volatile XacmlPdpResource pdpResource = null;

	/**
	 * Constructs API's root resource - PAP and PDP - from PDP configuration parameters and an attribute dictionary. Locations here may be any resource string supported by Spring ResourceLoader. More
	 * info: http://docs.spring.io/spring/docs/current/spring-framework-reference/html /resources.html
	 *
	 * For example: classpath:com/myapp/aaa.xsd, file:///data/bbb.xsd, http://myserver/ccc.xsd...
	 * 
	 * @param confLocation
	 *            location of PDP configuration XML file, compliant with the PDP XML schema (pdp.xsd)
	 * @param extensionXsdLocation
	 *            location of user-defined extension XSD (may be null if no extension to load), if exists; in such XSD, there must be a XSD namespace import for each extension used in the PDP
	 *            configuration, for example:
	 *
	 *            <pre>
	 * {@literal
	 * 		  <?xml version="1.0" encoding="UTF-8"?>
	 * <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
	 * 	<xs:annotation>
	 * 		<xs:documentation xml:lang="en">
	 * 			Import here the schema(s) of any XSD-defined PDP extension that you want to use in a PDP configuration: attribute finders, policy finders, etc.
	 * 			Indicate only the namespace here and use the XML catalog to resolve the schema location.
	 * 		</xs:documentation>
	 * 	</xs:annotation>
	 * 	<!-- Do not specify schema locations here. Define the schema locations in the XML catalog instead (see file 'catalog.xml'). -->
	 * 	<!--  Adding TestAttributeProvider extension for example -->
	 * 	<xs:import namespace="http://authzforce.github.io/core/xmlns/test/3" />
	 * </xs:schema>
	 * 			}
	 *            </pre>
	 *
	 *            In this example, the file at {@code catalogLocation} must define the schemaLocation for the imported namespace above using a line like this (for an XML-formatted catalog):
	 * 
	 *            <pre>
	 *            {@literal
	 *            <uri name="http://authzforce.github.io/core/xmlns/test/3" uri=
	 * 	"classpath:org.ow2.authzforce.core.test.xsd" />
	 *            }
	 *            </pre>
	 * 
	 *            We assume that this XML type is an extension of one the PDP extension base types, 'AbstractAttributeProvider' (that extends 'AbstractPdpExtension' like all other extension base
	 *            types) in this case.
	 * @param catalogLocation
	 *            location of XML catalog for resolving XSDs imported by the extension XSD specified as 'extensionXsdLocation' argument (may be null if 'extensionXsdLocation' is null)
	 * @param xacmlJsonPolicyFilenameSuffix
	 *            XACML/JSON filename suffix of policy files in policy repository
	 * @param driverAccessPolicyJsonSchema
	 *            JSON schema of DRIVER's access policy
	 * @param driverToXacmlJsonPolicyFtlLocation
	 *            location of Driver+-to-XACML/JSON access policy transformation's Freemarker template
	 * @throws java.lang.IllegalArgumentException
	 *             if {@code pdpConf.getXacmlExpressionFactory() == null || pdpConf.getRootPolicyProvider() == null}
	 * @throws java.io.IOException
	 *             error closing {@code pdpConf.getRootPolicyProvider()} when static resolution is to be used
	 * 
	 */
	public AuthzWsJaxrsRootResource(final Resource confLocation, final String catalogLocation, final String extensionXsdLocation, final String xacmlJsonPolicyFilenameSuffix,
	        final Schema driverAccessPolicyJsonSchema, final String driverToXacmlJsonPolicyFtlLocation) throws IllegalArgumentException, IOException
	{
		Preconditions.checkArgument(confLocation != null && catalogLocation != null && extensionXsdLocation != null);

		/*
		 * Policy repository settings
		 */
		final File confFile;
		try
		{
			confFile = confLocation.getFile();
		}
		catch (final FileNotFoundException e)
		{
			throw new RuntimeException("Could not resolve input PDP configuration location to a file on the file system (" + confLocation + ").", e);
		}

		if (confFile == null || !confFile.exists())
		{
			// no property replacement of PARENT_DIR
			throw new RuntimeException("Invalid configuration file location: No file exists at: " + confFile);
		}

		/*
		 * Configuration file exists Set property PARENT_DIR in environment properties for future replacement in configuration strings by PDP extensions using file paths
		 */
		final File confAbsFile = confFile.getAbsoluteFile();
		final File confAbsFileParent = confAbsFile.getParentFile();
		// LOGGER.debug("Config file's parent directory: {}", confAbsFileParent);
		final String propVal = confAbsFileParent.toURI().toString();
		// LOGGER.debug("Property {} = {}", EnvironmentPropertyName.PARENT_DIR, propVal);
		this.pdpEnvProps = new DefaultEnvironmentProperties(Collections.singletonMap(EnvironmentPropertyName.PARENT_DIR, propVal));

		final PdpModelHandler pdpModelHandler = new PdpModelHandler(catalogLocation, extensionXsdLocation);
		try
		{
			this.pdpJaxbConf = pdpModelHandler.unmarshal(new StreamSource(confAbsFile), Pdp.class);
		}
		catch (final JAXBException e)
		{
			throw new IllegalArgumentException("Invalid PDP configuration file: " + confAbsFile, e);
		}

		final AbstractPolicyProvider refPolicyProviderConf = pdpJaxbConf.getRefPolicyProvider();
		if (!(refPolicyProviderConf instanceof StaticRefPolicyProvider))
		{
			throw new RuntimeException("Invalid PDP configuration: refPolicyProvider not instance of " + StaticRefPolicyProvider.class);
		}

		final List<String> policyLocationPatterns = ((StaticRefPolicyProvider) refPolicyProviderConf).getPolicyLocations();
		if (policyLocationPatterns.size() != 1)
		{
			throw new RuntimeException("Invalid PDP configuration: refPolicyProvider must have one and only one policyLocation");
		}

		final String policyLocationPattern = policyLocationPatterns.iterator().next();
		final String policyLocationPatternAfterReplacement = this.pdpEnvProps.replacePlaceholders(policyLocationPattern);
		final int slashWildcardPatternIndex;
		if (!policyLocationPatternAfterReplacement.startsWith(ResourceUtils.FILE_URL_PREFIX) || (slashWildcardPatternIndex = policyLocationPatternAfterReplacement.indexOf("/*")) < 0)
		{
			throw new RuntimeException("Invalid PDP configuration: refPolicyProvider's policyLocation is not a file: URI or not a glob pattern: " + policyLocationPatternAfterReplacement);
		}

		// this is a file glob pattern
		/*
		 * Policies directory
		 */
		/*
		 * If we don't use URI before calling Paths.get(), this fails on Windows (string starting with /C:/... is not allowed by the Paths.get() API)
		 */
		final URI policiesDirUri = URI.create(policyLocationPatternAfterReplacement.substring(0, slashWildcardPatternIndex));
		final java.nio.file.Path policiesDir = Paths.get(policiesDirUri);

		/*
		 * Policy file suffix (part after wildcard(s))
		 */
		final int lastWildcardIndex = policyLocationPatternAfterReplacement.lastIndexOf('*');
		final String pdpInputPolicyFilenameSuffix = policyLocationPatternAfterReplacement.substring(lastWildcardIndex + 1);
		this.prpDao = new FsBasedPrpDao(policiesDir, pdpInputPolicyFilenameSuffix, xacmlJsonPolicyFilenameSuffix);

		// if (LOGGER.isDebugEnabled())
		// {
		// Beware of autoboxing which causes call to
		// Integer.valueOf(...) on policyLocationIndex
		// LOGGER.debug("Policy location #{} is a filepath pattern (found '/*') -> expanding to all files in directory '{}' with suffix '{}'", policyLocationIndex, directoryLocation,
		// globPattern);
		// }

		final PdpEngineConfiguration pdpEngineConf = new PdpEngineConfiguration(pdpJaxbConf, this.pdpEnvProps);
		this.pdpResource = new XacmlPdpResource(pdpEngineConf);

		this.driverAccessPolicyHandler = new DriverAccessPolicyHandler(driverAccessPolicyJsonSchema, driverToXacmlJsonPolicyFtlLocation);
	}

	/**
	 * Get single matrix argument
	 * 
	 * @param pathSegment
	 * @return single matrix parameter name and value, or null if no matrix parameter
	 */
	private static Entry<String, String> getSingleMatrixArg(final PathSegment pathSegment)
	{
		assert pathSegment != null;
		final MultivaluedMap<String, String> matrixParams = pathSegment.getMatrixParameters();

		if (matrixParams == null || matrixParams.isEmpty())
		{
			return null;
		}

		if (matrixParams.size() > 1)
		{
			throw new BadRequestException("Too many matrix parameters (expected: one and only one)");
		}

		final Entry<String, List<String>> param0 = matrixParams.entrySet().iterator().next();
		final String param0Key = param0.getKey();

		final List<String> param0Vals = param0.getValue();
		if (param0Vals.isEmpty() || param0Vals.size() > 1)
		{
			throw new BadRequestException("Matrix parameter '" + param0Key + "' has no value or more than one (expected: one and only one)");
		}

		final String param0Val0 = param0Vals.iterator().next();

		return new AbstractMap.SimpleImmutableEntry<>(param0Key, param0Val0);
	}

	private static String getChildPolicyId(final String parentPolicyId, final Entry<String, String> matrixArg)
	{

		/*
		 * Check whether matching parent and child policies already exist, ie whether directories named '{policyId} and '{policyId}#param0=val0' exist, to get current version (and increment for the
		 * new policy)
		 */
		return parentPolicyId + "#" + matrixArg.getKey() + "=" + matrixArg.getValue();
	}

	/**
	 * Get the latest version of a top-level policy in XACML/JSON format
	 * 
	 * @param policyId
	 *            top-level policy ID
	 * 
	 * 
	 * @return the child policy of policy {policyId} with Target = [a1=val1 AND a2=val2, etc.] (in XACML, this is a sequence of AnyOf, where each AnyOf is a single Allof with a single Match) where aN
	 *         is an attribute alias defined by {@code attributeDictionary} arg to {@link #AuthzWsJaxrsRootResource(Resource, String, String, String, Resource, String)}
	 */
	@GET
	@Path("/pap/policies/{policyId}")
	@Produces({ "application/json" })
	public JSONObject getLatestPolicyVersion(@PathParam("policyId") final String policyId)
	{
		final Optional<JSONObject> optJSONObject = this.prpDao.getLatestPolicyVersionContent(policyId, Optional.empty());
		if (!optJSONObject.isPresent())
		{
			throw new NotFoundException("Policy '" + policyId + "' not found");
		}

		return optJSONObject.get();
	}

	/**
	 * Updates access policy in DRIVER/JSON format
	 * 
	 * @param policyId
	 *            top-level policy ID
	 * 
	 * @param pathSegments
	 *            path segments {@code policies;a1=val1;a2=val2/...}
	 * 
	 * 
	 * @param validChildPolicyInDriverFormat
	 *            Driver+-JSON-formatted policy that is a child of the top-level policy identified by {@code policyId} (must be validated against schema by Json provider in Spring/JAX-RS service
	 *            configuration
	 * 
	 * @return creates/updates the child policy of policy {policyId} with Target = [a1=val1 AND a2=val2, etc.] (in XACML, this is a sequence of AnyOf, where each AnyOf is a single Allof with a single
	 *         Match) where aN is an attribute alias defined by {@code attributeDictionary} arg to {@link #AuthzWsJaxrsRootResource(Resource, String, String, String, Resource, String)}
	 */
	@PUT
	@Path("/pap/policies/{policyId}/{var: .*}")
	@Produces({ "application/json" })
	@Consumes({ "application/json" })
	public JSONObject setChildPolicyFromDriverFormat(@PathParam("policyId") final String policyId, @PathParam("var") final List<PathSegment> pathSegments,
	        final JSONObject validChildPolicyInDriverFormat)
	{
		if (pathSegments.size() > 1)
		{
			throw new BadRequestException("Too many path segments: " + pathSegments.size() + " (> 1)");
		}

		final PathSegment pathSeg0 = pathSegments.get(0);
		if (!pathSeg0.getPath().equals("policies"))
		{
			throw new BadRequestException("Unexpected path in last segment: " + pathSeg0.getPath() + ". Expected: 'policies'");
		}

		final Entry<String, String> matrixArg = getSingleMatrixArg(pathSegments.get(0));
		if (matrixArg == null)
		{
			throw new BadRequestException("Missing matrix parameter");
		}

		/*
		 * Check whether matching parent and child policies already exist, ie whether directories named '{policyId} and '{policyId}#param0=val0' exist, to get current version (and increment for the
		 * new policy)
		 */
		final String childPolicyId = getChildPolicyId(policyId, matrixArg);

		/*
		 * Verify parameter name is an attribute alias/key in attribute dictionary
		 */
		// final JSONObject jsonAttDesignator = jsonAttributeDesignatorsByAlias.get(matrixArg.getKey());
		// if (jsonAttDesignator == null)
		// {
		// throw new BadRequestException("Invalid matrix parameter: '" + matrixArg.getKey() + "' (no corresponding XACML attribute definition registered)");
		// }

		/*
		 * We assume the constructor made sure there is always a *-equal function corresponding to the datatype of jsonAttDesignator, else fatal error
		 */
		// final String attType = jsonAttDesignator.getString("dataType");
		// final String equalFunctionId = this.equalFunctionsByDatatype.get(attType);
		// if (equalFunctionId == null)
		// {
		// throw new RuntimeException("No *-equal function registered for attribute datatype: " + attType);
		// }

		// final JSONArray xacmlJsonTargetValue = newXacmlJsonTargetValue(equalFunctionId, matrixArg.getValue(), jsonAttDesignator);

		final Optional<PolicyVersion> latestChildPolicyVersion;
		final String newChildPolicyVersion;

		synchronized (this.prpDao)
		{
			final Optional<PolicyVersion> optLatestPolicyVersion = this.prpDao.getLatestPolicyVersion(policyId);
			if (!optLatestPolicyVersion.isPresent())
			{
				throw new NotFoundException("Policy '" + policyId + "' not found");
			}

			latestChildPolicyVersion = this.prpDao.getLatestPolicyVersion(childPolicyId);

			if (!latestChildPolicyVersion.isPresent())
			{
				newChildPolicyVersion = DEFAULT_POLICY_VERSION;
			}
			else
			{
				newChildPolicyVersion = incrementPolicyVersion(latestChildPolicyVersion.get().toString());
			}

			/*
			 * Convert to AuthzForce/XACML/JSON format, increase current policy version if already exists, else default: 1.0. childPolicyInDriverFormat is assumed validated against schema by
			 * JsonRiJaxrsProvider in JAX-RS service configuration
			 */
			final JSONObject xacmlJsonPolicy = driverAccessPolicyHandler.toXacmlJsonPolicy(validChildPolicyInDriverFormat, childPolicyId, newChildPolicyVersion, matrixArg.getValue());

			/*
			 * Validate result against schema
			 */
			XacmlJsonUtils.POLICY_SCHEMA.validate(xacmlJsonPolicy);

			/*
			 * It is not absolutely necessary to wrap the JSON object with the root key 'policy' but we do it here for readability: the policy store's admin can guess the type of data in the JSON file
			 * by looking at the root key.
			 */
			final JSONObject wrappedChildXacmlJsonPolicy = new JSONObject(Collections.singletonMap("policy", xacmlJsonPolicy));

			/*
			 * Write/commit new policy version
			 */
			try (final Transaction tx = this.prpDao.newTx())
			{
				this.prpDao.addPolicyVersion(tx, childPolicyId, newChildPolicyVersion, wrappedChildXacmlJsonPolicy, Optional.empty());
				/*
				 * BEGIN DRIVER+-specific stuff: commit policy in DRIVER+ format
				 * 
				 * TODO: to be removed on the long term
				 */
				this.prpDao.addPolicyVersion(tx, childPolicyId, newChildPolicyVersion, validChildPolicyInDriverFormat, Optional.of(DRIVER_ACCESS_POLICY_CONTENT_TYPE_ID));

				/*
				 * Make sure that the parent policy has a reference to the child policy
				 */
				final Optional<JSONObject> wrappedParentXacmlJsonPolicy = this.prpDao.getLatestPolicyVersionContent(policyId, Optional.empty());
				if (!wrappedParentXacmlJsonPolicy.isPresent())
				{
					throw new NotFoundException("Policy '" + policyId + "' not found");
				}

				final JSONObject parentXacmlJsonPolicy = wrappedParentXacmlJsonPolicy.get().optJSONObject("policy");
				if (parentXacmlJsonPolicy == null)
				{
					throw new RuntimeException("Invalid policy '" + policyId + "' (latest version): no 'policy' root key");
				}

				final boolean isParentPolicyUpdated;
				final JSONArray policiesJsonArray = parentXacmlJsonPolicy.optJSONArray("policies");
				final JSONArray newPoliciesJsonArray;
				if (policiesJsonArray == null)
				{
					newPoliciesJsonArray = new JSONArray();
					isParentPolicyUpdated = true;
					parentXacmlJsonPolicy.put("policies", newPoliciesJsonArray);
				}
				else
				{
					newPoliciesJsonArray = policiesJsonArray;
					isParentPolicyUpdated = !StreamSupport.stream(policiesJsonArray.spliterator(), true).anyMatch(json -> {
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

				if (isParentPolicyUpdated)
				{
					final JSONObject wrappedChildPolicyRefJsonObject = new JSONObject(Collections.singletonMap("policyRef", new JSONObject(Collections.singletonMap("id", childPolicyId))));
					newPoliciesJsonArray.put(wrappedChildPolicyRefJsonObject);
					final String latestParentPolicyVersion = parentXacmlJsonPolicy.optString("version");
					if (latestParentPolicyVersion == null)
					{
						throw new RuntimeException("Invalid policy '" + policyId + "' (latest version): no 'version' key");
					}

					final String newParentPolicyVersion = incrementPolicyVersion(latestParentPolicyVersion);
					this.prpDao.addPolicyVersion(tx, policyId, newParentPolicyVersion, wrappedParentXacmlJsonPolicy.get(), Optional.empty());
				}

				/*
				 * Create new PDP resource from this new update of policies
				 */
				final PdpEngineConfiguration pdpEngineConf;
				try
				{
					pdpEngineConf = new PdpEngineConfiguration(this.pdpJaxbConf, this.pdpEnvProps);
					this.pdpResource = new XacmlPdpResource(pdpEngineConf);
				}
				catch (final IOException e)
				{
					throw new RuntimeException("Error loading PDP configuration after policy update", e);
				}

				/*
				 * All right
				 */
				tx.commit();
			} /*
			   * END try(tx)
			   */
			catch (final Exception e)
			{
				throw new RuntimeException("Error closing policy update transaction", e);
			}
		} /*
		   * END synchronized
		   */

		return validChildPolicyInDriverFormat;

	}

	/**
	 * Updates access policy in AuthzForce XACML/JSON format
	 * 
	 * @param string
	 * @param xacmlJsonTargetValue
	 * @param newChildPolicyVersion
	 * @param childPolicyId
	 * @param defaultRuleCombiningAlgo
	 * 
	 * 
	 * @param xacmlPolicy
	 *            AuthzForce XACML/JSON formatted policy
	 * 
	 * @return the updated policy
	 */
	// @PUT
	// @Path("/policies/{policyId}/{var:policies}")
	// @Produces({ "application/xacml+json" })
	// @Consumes({ "application/xacml+json" })
	// public JSONObject updatePolicyWithAuthzForceXacmlFormat(@PathParam("var") PathSegment pathSegment, JSONObject xacmlPolicy)
	// {
	// TODO
	// }

	private static String getChildPolicyId(final String policyId, final List<PathSegment> pathSegments)
	{
		if (pathSegments.size() > 1)
		{
			throw new BadRequestException("Too many path segments: " + pathSegments.size() + " (> 1)");
		}

		final PathSegment pathSeg0 = pathSegments.get(0);
		if (!pathSeg0.getPath().equals("policies"))
		{
			throw new BadRequestException("Unexpected path in last segment: " + pathSeg0.getPath() + ". Expected: 'policies'");
		}

		final Entry<String, String> matrixArg = getSingleMatrixArg(pathSeg0);
		if (matrixArg == null)
		{
			throw new BadRequestException("Missing matrix parameter");
		}

		return getChildPolicyId(policyId, matrixArg);
	}

	/**
	 * Gets sub-policies of a given policy in Driver format
	 * 
	 * @param policyId
	 *            top-level policy ID
	 * 
	 * @param pathSegments
	 *            path segments {@code policies;a1=val1;a2=val2/...}
	 * 
	 * @return the child policy of policy {policyId} with Target = [a1=val1 AND a2=val2, etc.] (in XACML, this is a sequence of AnyOf, where each AnyOf is a single Allof with a single Match) where aN
	 *         is an attribute alias defined by {@code attributeDictionary} arg to {@link #AuthzWsJaxrsRootResource(Resource, String, String, String, Resource, String)}
	 */
	@GET
	@Path("/pap/policies/{policyId}/{var: .*}")
	@Produces({ "application/json" })
	public JSONObject getLatestChildPolicyVersionInDriverFormat(@PathParam("policyId") final String policyId, @PathParam("var") final List<PathSegment> pathSegments)
	{
		final String childPolicyId = getChildPolicyId(policyId, pathSegments);
		final Optional<JSONObject> optJSONObject = this.prpDao.getLatestPolicyVersionContent(childPolicyId, Optional.of(DRIVER_ACCESS_POLICY_CONTENT_TYPE_ID));
		if (!optJSONObject.isPresent())
		{
			throw new NotFoundException("");
		}

		return optJSONObject.get();
	}

	/**
	 * Deletes sub-policies (of a given top-level policy in DRIVER format
	 * 
	 * @param policyId
	 *            top-level policy ID
	 * 
	 * @param pathSegments
	 *            path segments {@code policies;a1=val1;a2=val2/...}
	 * 
	 * 
	 */
	@DELETE
	@Path("/pap/policies/{policyId}/{var: .*}")
	@Produces({ "application/json" })
	public void deleteChildPolicy(@PathParam("policyId") final String policyId, @PathParam("var") final List<PathSegment> pathSegments)
	{
		final String childPolicyId = getChildPolicyId(policyId, pathSegments);

		synchronized (this.prpDao)
		{

			/*
			 * Write/commit new policy version
			 */
			try (final Transaction tx = this.prpDao.newTx())
			{
				/*
				 * Remove reference from parent
				 * 
				 */
				final Optional<JSONObject> wrappedParentXacmlJsonPolicy = this.prpDao.getLatestPolicyVersionContent(policyId, Optional.empty());
				if (!wrappedParentXacmlJsonPolicy.isPresent())
				{
					throw new NotFoundException("Policy '" + policyId + "' not found");
				}

				final JSONObject parentXacmlJsonPolicy = wrappedParentXacmlJsonPolicy.get().optJSONObject("policy");
				if (parentXacmlJsonPolicy == null)
				{
					throw new RuntimeException("Invalid policy '" + policyId + "' (latest version): no 'policy' root key");
				}

				final boolean isParentPolicyUpdated;
				final JSONArray policiesJsonArray = parentXacmlJsonPolicy.optJSONArray("policies");
				if (policiesJsonArray == null)
				{
					isParentPolicyUpdated = false;
				}
				else
				{
					isParentPolicyUpdated = Iterators.removeIf(policiesJsonArray.iterator(), json -> {
						if (json instanceof JSONObject)
						{
							final JSONObject policyRefJsonObject = ((JSONObject) json).optJSONObject("policyRef");
							return policyRefJsonObject != null && policyRefJsonObject.getString("id").equals(childPolicyId);
						}
						return false;
					});
				}

				if (isParentPolicyUpdated)
				{
					final String latestParentPolicyVersion = parentXacmlJsonPolicy.optString("version");
					if (latestParentPolicyVersion == null)
					{
						throw new RuntimeException("Invalid policy '" + policyId + "' (latest version): no 'version' key");
					}

					final String newParentPolicyVersion = incrementPolicyVersion(latestParentPolicyVersion);
					this.prpDao.addPolicyVersion(tx, policyId, newParentPolicyVersion, wrappedParentXacmlJsonPolicy.get(), Optional.empty());
				}

				/*
				 * Delete the child policy
				 */
				this.prpDao.deletePolicy(tx, childPolicyId);

				/*
				 * Create new PDP resource from this new update of policies
				 */
				final PdpEngineConfiguration pdpEngineConf;
				try
				{
					pdpEngineConf = new PdpEngineConfiguration(this.pdpJaxbConf, this.pdpEnvProps);
					this.pdpResource = new XacmlPdpResource(pdpEngineConf);
				}
				catch (final IllegalArgumentException e)
				{
					/*
					 * FIXME: remove this line
					 */
					LOGGER.error("Error loading PDP configuration after policy update", e);
				}
				catch (final IOException e)
				{
					throw new RuntimeException("Error loading PDP configuration after policy update", e);
				}

				/*
				 * All right
				 */
				tx.commit();
			} /*
			   * END try(tx)
			   */
			catch (final IllegalArgumentException e)
			{
				throw e;
			}
			catch (final Exception e)
			{
				throw new RuntimeException("Policy update transaction failed due to internal error", e);
			}
		} /*
		   * END synchronized
		   */

	}

	// /**
	// * Evaluates XACML/XML Request
	// *
	// * @param request
	// * XACML/XML Request
	// *
	// * @return XACML/XML Response
	// */
	// @POST
	// @Produces({ "application/xml", "application/xacml+xml" })
	// @Consumes({ "application/xml", "application/xacml+xml" })
	// public Response evaluateXml(final Request request)
	// {
	// return this.pdpResource.evaluateXml(request);
	// }

	/**
	 * Evaluates XACML/JSON Request according to JSON Profile of XACML 3.0
	 * 
	 * @param request
	 *            XACML/JSON Request
	 * 
	 * @return XACML/JSON Response
	 */
	@POST
	@Path("/pdp")
	@Produces({ "application/json", "application/xacml+json" })
	@Consumes({ "application/json", "application/xacml+json" })
	public JSONObject evaluateJson(final JSONObject request)
	{
		return this.pdpResource.evaluateJson(request);
	}
}
