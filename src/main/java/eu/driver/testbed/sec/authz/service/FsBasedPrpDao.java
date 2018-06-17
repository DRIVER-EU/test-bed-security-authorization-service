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
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.xml.transform.stream.StreamSource;

import org.json.JSONObject;
import org.json.JSONTokener;
import org.ow2.authzforce.core.pdp.api.HashCollections;
import org.ow2.authzforce.core.pdp.api.XmlUtils;
import org.ow2.authzforce.core.pdp.api.policy.PolicyVersion;
import org.ow2.authzforce.xacml.json.model.XacmlJsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.FileSystemUtils;

import com.google.common.base.Preconditions;

import net.sf.saxon.s9api.SaxonApiException;
import net.sf.saxon.s9api.XdmAtomicValue;
import net.sf.saxon.s9api.Xslt30Transformer;
import net.sf.saxon.s9api.XsltExecutable;
import net.sf.saxon.trace.XSLTTraceListener;

/**
 * Filesystem-based XACML PRP DAO (PRP = Policy Repository Point, DAO = Data Access Object interface) implementation
 * 
 * TODO: replace this filesystem-based DAO with a a higher-performance embedded transactional key-value database.
 */
final class FsBasedPrpDao implements PrpDao
{
	private static final Logger LOGGER = LoggerFactory.getLogger(FsBasedPrpDao.class);

	private static final class TransactionImpl implements Transaction
	{
		private boolean isCommitted = false;
		/*
		 * Maintain list of created files for rollback in case of error. At most 3 files created: a new policy P1's directory and version file, and possibly a new version of a policy P2 with new
		 * reference to P1
		 */
		final Deque<java.nio.file.Path> createdFiles = new ArrayDeque<>(3);
		/*
		 * So far at most 1 file moved per transaction (when policy deleted)
		 */
		final Map<Path, Path> movedFileSourcesToTargets = HashCollections.newUpdatableMap(1);

		private void addCreatedFile(final Path p)
		{
			createdFiles.add(p);
		}

		public void addMoveFile(final Path policyDir, final Path backupDir)
		{
			movedFileSourcesToTargets.put(policyDir, backupDir);
		}

		@Override
		public void commit()
		{
			this.isCommitted = true;
		}

		@Override
		public void close() throws Exception
		{
			try
			{
				if (!isCommitted)
				{
					/*
					 * Abort transaction
					 */
					createdFiles.forEach(fp -> {
						/*
						 * delete directory only if empty, directories are last in the stack
						 */
						try
						{
							if (!Files.isDirectory(fp) || isDirectoryEmpty(fp))
							{
								Files.deleteIfExists(fp);
							}
						}
						catch (final IOException e)
						{
							throw new RuntimeException("Failed rollback after policy update transaction failed", e);
						}
					});

					movedFileSourcesToTargets.entrySet().forEach(movedFileEntry -> {
						try
						{
							/*
							 * move file back from target (entry value) to source (entry key)
							 */
							// Files.move() does not work in Docker container
							// Files.move(movedFileEntry.getValue(), movedFileEntry.getKey(), StandardCopyOption.REPLACE_EXISTING));
							final File from = movedFileEntry.getValue().toFile();
							final File to = movedFileEntry.getKey().toFile();
							FileSystemUtils.copyRecursively(from, to);
							FileSystemUtils.deleteRecursively(from);
						}
						catch (final IOException e)
						{
							throw new RuntimeException("Failed rollback after policy update transaction failed", e);
						}
					});
				}
			}
			finally
			{
				createdFiles.clear();
				movedFileSourcesToTargets.clear();
			}
		}

	}

	private static boolean isDirectoryEmpty(final Path directory) throws IOException
	{

		try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory))
		{
			return !directoryStream.iterator().hasNext();
		}
	}

	private static final String ORG_JSON_XML_TO_XACML_3_0_XSLT_LOCATION = AuthzWsJaxrsRootResource.class.getResource("xacml-json-to-xml.xslt").toString();
	private static final XsltExecutable ORG_JSON_XML_TO_XACML_3_0_XSLT;

	static
	{
		try
		{
			ORG_JSON_XML_TO_XACML_3_0_XSLT = XmlUtils.SAXON_PROCESSOR.newXsltCompiler().compile(new StreamSource(ORG_JSON_XML_TO_XACML_3_0_XSLT_LOCATION));
		}
		catch (final SaxonApiException e)
		{
			throw new RuntimeException("Cannot create processor of XSLT file (org.json.XML to XACML 3.0/XML transformation): " + ORG_JSON_XML_TO_XACML_3_0_XSLT_LOCATION, e);
		}
	}

	private final Path policiesDir;
	private final String pdpInputPolicyFilenameSuffix;
	private final String jsonPolicyFilenameSuffix;

	private static void convertXacmlJsonToXmlPolicy(final JSONObject inputJson, final Path outXmlFile)
	{
		final Xslt30Transformer xslt = ORG_JSON_XML_TO_XACML_3_0_XSLT.load30();
		xslt.setTraceListener(LOGGER.isDebugEnabled() ? new XSLTTraceListener() : null);

		final String policyStr = inputJson.toString();
		LOGGER.debug("Applying XSLT '{}' to XACML/JSON policy: {}", ORG_JSON_XML_TO_XACML_3_0_XSLT_LOCATION, policyStr);
		try
		{
			xslt.setGlobalContextItem(new XdmAtomicValue(policyStr));
			/*
			 * Call default template "xsl:initial-template"
			 */
			xslt.callTemplate(null, xslt.newSerializer(outXmlFile.toFile()));
		}
		catch (final SaxonApiException e)
		{
			throw new RuntimeException("Failed to transform XACML 3.0/JSON into XACML 3.0/XML policy", e);
		}
	}

	FsBasedPrpDao(final Path policiesDirectory, final String pdpInputPolicyFilenameSuffix, final String xacmlJsonPolicyFilenameSuffix)
	{
		Preconditions.checkArgument(policiesDirectory != null && pdpInputPolicyFilenameSuffix != null, "policiesDirectory or pdpInputPolicyFilenameSuffix undefined");

		if (!Files.isReadable(policiesDirectory) || !Files.isWritable(policiesDirectory))
		{
			throw new IllegalArgumentException("Policies directory '" + policiesDirectory + "' does not exist or not readable or not writeable: " + Files.isReadable(policiesDirectory) + ", "
			        + Files.isWritable(policiesDirectory));
		}

		this.pdpInputPolicyFilenameSuffix = pdpInputPolicyFilenameSuffix;
		this.jsonPolicyFilenameSuffix = xacmlJsonPolicyFilenameSuffix;

		/*
		 * Verify XACML/JSON policies in repository and convert to PDP-compatible XACML/XML versions if not done yet
		 */

		try (final Stream<Path> jsonPolicyFileStream = Files.find(policiesDirectory, 2, (path, attrs) -> attrs.isRegularFile() && path.getFileName().toString().endsWith(jsonPolicyFilenameSuffix)))
		{
			jsonPolicyFileStream.forEach(jsonFile -> {
				LOGGER.debug("Checking policy file: '{}'", jsonFile);
				/*
				 * Validate
				 */
				final JSONObject jsonObject;
				try (final Reader reader = Files.newBufferedReader(jsonFile, StandardCharsets.UTF_8))
				{
					jsonObject = new JSONObject(new JSONTokener(reader));
				}
				catch (final IOException e)
				{
					throw new RuntimeException("Error verifying policy repository: failed to read file: " + jsonFile, e);
				}

				final JSONObject jsonPolicy = jsonObject.optJSONObject("policy");
				if (jsonPolicy == null)
				{
					throw new IllegalArgumentException("Invalid XACML/JSON policy file: '" + jsonFile + "': root key != 'policy'");
				}

				XacmlJsonUtils.POLICY_SCHEMA.validate(jsonPolicy);
				/*
				 * Check if the corresponding PDP-compatible (XACML/XML) version exists
				 */
				final String jsonFilename = jsonFile.getFileName().toString();
				final String pdpInputFilename = jsonFilename.substring(0, jsonFilename.length() - jsonPolicyFilenameSuffix.length()) + pdpInputPolicyFilenameSuffix;
				final Path pdpInputPolicyFile = jsonFile.getParent().resolve(pdpInputFilename);
				if (!Files.exists(pdpInputPolicyFile))
				{
					/*
					 * We have to create it: transform the JSON to XML version of XACML policy
					 */
					LOGGER.debug("PDP-compatible policy file missing: '{}' -> generating/converting from file: '{}'", pdpInputPolicyFile, jsonFile);
					convertXacmlJsonToXmlPolicy(jsonObject, pdpInputPolicyFile);
				}
			});
		}
		catch (IOException | DirectoryIteratorException e)
		{
			// IOException can never be thrown by the iteration.
			// In this snippet, it can only be thrown by newDirectoryStream.
			throw new RuntimeException("Error verifying policy repository in directory: " + policiesDirectory, e);
		}

		this.policiesDir = policiesDirectory;
	}

	@Override
	public Transaction newTx()
	{
		return new TransactionImpl();
	}

	private String getFilenameSuffix(final Optional<String> customContentTypeId)
	{
		assert customContentTypeId != null;
		final String filenameSuffix;
		if (customContentTypeId.isPresent())
		{
			filenameSuffix = "." + customContentTypeId.get();
			if (filenameSuffix.equals(this.pdpInputPolicyFilenameSuffix) || filenameSuffix.equals(this.jsonPolicyFilenameSuffix))
			{
				throw new IllegalArgumentException(
				        "Invalid customContentTypeId. Expected different from '" + pdpInputPolicyFilenameSuffix.substring(1) + "' and '" + this.jsonPolicyFilenameSuffix.substring(1) + "'");
			}
		}
		else
		{
			filenameSuffix = this.jsonPolicyFilenameSuffix;
		}

		return filenameSuffix;
	}

	@Override
	public void addPolicyVersion(final Transaction tx, final String policyId, final String policyVersion, final JSONObject policyContent, final Optional<String> customContentTypeId)
	{
		assert tx != null && policyId != null && policyVersion != null && policyContent != null && customContentTypeId != null;
		final FsBasedPrpDao.TransactionImpl txImpl = (FsBasedPrpDao.TransactionImpl) tx;

		final Path policyDir = policiesDir.resolve(policyId);
		if (!Files.isDirectory(policyDir))
		{
			try
			{
				Files.createDirectory(policyDir);
				txImpl.addCreatedFile(policyDir);
			}
			catch (final IOException e)
			{
				throw new RuntimeException("Error creating policy-specific directory: " + policyDir, e);
			}
		}

		if (!customContentTypeId.isPresent())
		{
			/*
			 * Default XACML/JSON content to be converted to XACML/XML
			 */
			final Path newPdpInputPolicyVersionFile = policyDir.resolve(policyVersion + this.pdpInputPolicyFilenameSuffix);
			/*
			 * Make sure the version in policyContent is up-to-date
			 */
			policyContent.getJSONObject("policy").put("version", policyVersion);
			convertXacmlJsonToXmlPolicy(policyContent, newPdpInputPolicyVersionFile);
			txImpl.addCreatedFile(newPdpInputPolicyVersionFile);
		}

		final Path newPolicyVersionFile = policyDir.resolve(policyVersion + getFilenameSuffix(customContentTypeId));
		try (final BufferedWriter writer = Files.newBufferedWriter(newPolicyVersionFile, StandardCharsets.UTF_8, StandardOpenOption.CREATE))
		{
			policyContent.write(writer);
			txImpl.addCreatedFile(newPolicyVersionFile);
		}
		catch (final IOException e)
		{
			throw new RuntimeException("Error writing new policy to file: " + newPolicyVersionFile, e);
		}
	}

	private Optional<PolicyVersion> getLatestPolicyVersion(final Path policyVersionsDirectory)
	{
		try (final DirectoryStream<Path> dirStream = Files.newDirectoryStream(policyVersionsDirectory, "*" + pdpInputPolicyFilenameSuffix))
		{
			return StreamSupport.stream(dirStream.spliterator(), true).filter(f -> Files.isRegularFile(f)).map(f -> getPolicyVersion(f, this.pdpInputPolicyFilenameSuffix))
			        .max(PolicyVersion::compareTo);
		}
		catch (IOException | DirectoryIteratorException e)
		{
			// IOException can never be thrown by the iteration.
			// In this snippet, it can only be thrown by newDirectoryStream.
			throw new RuntimeException("Error getting latest policy version file in directory: " + policyVersionsDirectory, e);
		}
	}

	@Override
	public Optional<PolicyVersion> getLatestPolicyVersion(final String policyId)
	{
		assert policyId != null;

		final Path policyVersionsDir = policiesDir.resolve(policyId);
		if (!Files.isDirectory(policyVersionsDir))
		{
			return Optional.empty();
		}

		return getLatestPolicyVersion(policyVersionsDir);
	}

	private static JSONObject getJson(final Path path)
	{
		assert Files.isRegularFile(path);

		try (final BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8))
		{
			return new JSONObject(new JSONTokener(reader));
		}
		catch (final IOException e)
		{
			throw new RuntimeException("Error reading JSON from file: " + path, e);
		}
	}

	@Override
	public Optional<JSONObject> getPolicy(final String policyId, final Optional<PolicyVersion> policyVersion)
	{
		assert policyId != null && policyVersion != null;

		final Path policyVersionsDir = policiesDir.resolve(policyId);
		if (!Files.isDirectory(policyVersionsDir))
		{
			return Optional.empty();
		}

		/*
		 * Each filename is named {policyVersion}{pdpInputPolicyFilenameSuffix}, e.g. '1.0.xacml.xml'
		 */
		final String policyVersionStr;
		if (policyVersion.isPresent())
		{
			policyVersionStr = policyVersion.get().toString();
		}
		else
		{
			/*
			 * Version undefined -> get the latest
			 */
			policyVersionStr = getLatestPolicyVersion(policyVersionsDir).toString();
		}

		final Path jsonPolicyVersionFile = policyVersionsDir.resolve(policyVersionStr + this.jsonPolicyFilenameSuffix);
		if (!Files.isRegularFile(jsonPolicyVersionFile))
		{
			return Optional.empty();
		}

		return Optional.of(getJson(jsonPolicyVersionFile));
	}

	private static PolicyVersion getPolicyVersion(final Path policyFile, final String filenameSuffix)
	{
		final String fileName = policyFile.getFileName().toString();
		final String version = fileName.substring(0, fileName.length() - filenameSuffix.length());
		return new PolicyVersion(version);
	}

	private Optional<JSONObject> getLatestPolicyVersionFileContent(final String policyId, final String filenameSuffix)
	{
		assert policyId != null && filenameSuffix != null;

		final Path policyVersionsDir = policiesDir.resolve(policyId);
		if (!Files.isDirectory(policyVersionsDir))
		{
			return Optional.empty();
		}

		final Optional<Path> latestPolicyVersionFilePath;
		try (final DirectoryStream<Path> dirStream = Files.newDirectoryStream(policyVersionsDir, "*" + filenameSuffix))
		{
			latestPolicyVersionFilePath = StreamSupport.stream(dirStream.spliterator(), true).filter(f -> Files.isRegularFile(f))
			        .max((f1, f2) -> getPolicyVersion(f1, filenameSuffix).compareTo(getPolicyVersion(f2, filenameSuffix)));
		}
		catch (IOException | DirectoryIteratorException e)
		{
			// IOException can never be thrown by the iteration.
			// In this snippet, it can only be thrown by newDirectoryStream.
			throw new RuntimeException("Error getting last policy version file in directory: " + policyVersionsDir, e);
		}

		return latestPolicyVersionFilePath.isPresent() ? Optional.of(getJson(latestPolicyVersionFilePath.get())) : Optional.empty();
	}

	@Override
	public Optional<JSONObject> getLatestPolicyVersionContent(final String policyId, final Optional<String> customPolicyContentTypeId)
	{
		return getLatestPolicyVersionFileContent(policyId, getFilenameSuffix(customPolicyContentTypeId));
	}

	@Override
	public void deletePolicy(final Transaction tx, final String policyId)
	{
		assert tx != null && policyId != null;
		final FsBasedPrpDao.TransactionImpl txImpl = (FsBasedPrpDao.TransactionImpl) tx;

		final Path policyDir = policiesDir.resolve(policyId);
		if (!Files.isDirectory(policyDir))
		{
			/*
			 * Policy directory already gone / does not exist, so we're done
			 */
			return;
		}

		/*
		 * Move to temporary backup in case transaction fails (in which case we need to rollback)
		 */
		final String tmpDirPrefix = FsBasedPrpDao.class.getPackage().getName() + "#backup.";
		try
		{
			final Path tmpDir = Files.createTempDirectory(tmpDirPrefix);
			final Path policyBackupDir = tmpDir.resolve("policies#" + policyId);
			// Files.move() does not work in Docker container
			// Files.move(policyDir, policyBackupDir, StandardCopyOption.REPLACE_EXISTING);
			final File policyDirFile = policyDir.toFile();
			FileSystemUtils.copyRecursively(policyDirFile, policyBackupDir.toFile());
			FileSystemUtils.deleteRecursively(policyDirFile);
			txImpl.addMoveFile(policyDir, policyBackupDir);
		}
		catch (final IOException e)
		{
			throw new RuntimeException("Failed to remove policy '" + policyId + "' from repository (trying to move to temporary backup directory with prefix '" + tmpDirPrefix + "')", e);
		}
	}

	/*
	 * Testing XACML/JSON to XACML/XML XSLT
	 */
	// public static void main(final String... args) throws SaxonApiException, IOException, JAXBException
	// {
	// final Path path = Paths.get("src/test/resources/policies/resource.type=TOPIC/1.0.json");
	// assert Files.isRegularFile(path);
	//
	// final String jsonStr = new String(Files.readAllBytes(path));
	//
	// final Xslt30Transformer xslt = ORG_JSON_XML_TO_XACML_3_0_XSLT.load30();
	// xslt.setGlobalContextItem(new XdmAtomicValue(jsonStr));
	// /*
	// * Call default template "xsl:initial-template"
	// */
	// final StringWriter strWriter = new StringWriter();
	// xslt.callTemplate(null, xslt.newSerializer(strWriter));
	// final String xmlStr = strWriter.toString();
	// System.out.println(xmlStr);
	// Xacml3JaxbHelper.createXacml3Unmarshaller().unmarshal(new StringReader(xmlStr));
	// }

}