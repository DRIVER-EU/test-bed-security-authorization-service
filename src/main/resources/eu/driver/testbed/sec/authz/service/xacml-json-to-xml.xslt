<xsl:stylesheet
	version="3.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xpath-default-namespace="http://www.w3.org/2005/xpath-functions"
	expand-text="yes"
	xmlns:xacml="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17">
	<!-- Reference example for JSON to XML transformation: https://www.saxonica.com/papers/xmlprague-2016mhk.pdf -->
	<!-- expand-text option allows to use text value templates in XSLT 3.0 -->
	<xsl:output
		encoding="UTF-8"
		indent="yes"
		method="xml" />

	<!-- This element removes indentation with Xalan 2.7.1 (indentation preserved with Saxon 9.6.0.4). -->
	<!-- <xsl:strip-space elements="*" /> -->

	<xsl:template name="xsl:initial-template">
		<!-- <xsl:copy-of select="json-to-xml(.)" /> -->
		<xsl:apply-templates select="json-to-xml(.)" />
	</xsl:template>

	<xsl:template match="map[@key='attributeDesignator']">
		<xacml:AttributeDesignator
			DataType="{string[@key='dataType']}"
			MustBePresent="{boolean[@key='mustBePresent']}"
			Category="{string[@key='category']}"
			AttributeId="{string[@key='id']}">
			<xsl:if test="string[@key='issuer']">
				<xsl:attribute
					name="Issuer"
					select="string[@key='issuer']" />
			</xsl:if>
		</xacml:AttributeDesignator>
	</xsl:template>

	<xsl:template match="array[@key='target']">
		<xacml:Target>
			<xsl:for-each select="array">
				<xacml:AnyOf>
					<xsl:for-each select="array">
						<xacml:AllOf>
							<xsl:for-each select="map">
								<xacml:Match MatchId="{string[@key='matchFunction']}">
									<xacml:AttributeValue>
										<xsl:attribute name="DataType">
									<xsl:choose>
									<!-- AttributeValue's datatype is the same as the AttributeDesignator/Selector's except for certain functions -->
									<xsl:when test="string[@key='matchFunction'] = 'urn:oasis:names:tc:xacml:3.0:function:anyURI-starts-with'">http://www.w3.org/2001/XMLSchema#string</xsl:when>
									<xsl:when test="string[@key='matchFunction'] = 'urn:oasis:names:tc:xacml:3.0:function:anyURI-ends-with'">http://www.w3.org/2001/XMLSchema#string</xsl:when>
									<xsl:when test="string[@key='matchFunction'] = 'urn:oasis:names:tc:xacml:3.0:function:anyURI-contains'">http://www.w3.org/2001/XMLSchema#string</xsl:when>
									<xsl:when test="string[@key='matchFunction'] = 'urn:oasis:names:tc:xacml:2.0:function:anyURI-regexp-match'">http://www.w3.org/2001/XMLSchema#string</xsl:when>
									<xsl:when test="string[@key='matchFunction'] = 'urn:oasis:names:tc:xacml:2.0:function:ipAddress-regexp-match'">http://www.w3.org/2001/XMLSchema#string</xsl:when>
									<xsl:when test="string[@key='matchFunction'] = 'urn:oasis:names:tc:xacml:2.0:function:dnsName-regexp-match'">http://www.w3.org/2001/XMLSchema#string</xsl:when>
									<xsl:when test="string[@key='matchFunction'] = 'urn:oasis:names:tc:xacml:2.0:function:rfc822Name-regexp-match'">http://www.w3.org/2001/XMLSchema#string</xsl:when>
									<xsl:when test="string[@key='matchFunction'] = 'urn:oasis:names:tc:xacml:2.0:function:x500Name-regexp-match'">http://www.w3.org/2001/XMLSchema#string</xsl:when>
									<xsl:when test="string[@key='matchFunction'] = 'urn:oasis:names:tc:xacml:1.0:function:rfc822Name-match'">http://www.w3.org/2001/XMLSchema#string</xsl:when>
									<xsl:otherwise>{map[@key='attributeDesignator']/string[@key='dataType']}</xsl:otherwise>
									</xsl:choose>
									</xsl:attribute>
										<xsl:value-of select="string[@key='value']" />
									</xacml:AttributeValue>
									<!-- TODO: support AttributeSelector -->
									<xsl:apply-templates select="map[@key='attributeDesignator']" />
								</xacml:Match>
							</xsl:for-each>
						</xacml:AllOf>
					</xsl:for-each>
				</xacml:AnyOf>
			</xsl:for-each>
		</xacml:Target>
	</xsl:template>

	<xsl:template match="array[@key='rules']/map">
		<xacml:Rule
			Effect="{string[@key='effect']}"
			RuleId="{string[@key='id']}">
			<xsl:if test="string[@key='description']">
				<xacml:Description>{string[@key='description']}</xacml:Description>
			</xsl:if>
			<xsl:choose>
				<xsl:when test="array[@key='target']">
					<xsl:apply-templates select="array[@key='target']" />
				</xsl:when>
				<xsl:otherwise>
					<xacml:Target />
				</xsl:otherwise>
			</xsl:choose>
			<!-- TODO: support Condition, Advice/ObligationExpressions -->
		</xacml:Rule>
	</xsl:template>

	<xsl:template match="map[@key='policy']">
		<xsl:choose>
			<xsl:when test="array[@key='policies']">
				<xacml:PolicySet
					PolicyCombiningAlgId="{string[@key='combiningAlgId']}"
					PolicySetId="{string[@key='id']}">
					<xsl:attribute name="Version">
					<xsl:choose>
						<xsl:when test="string[@key='version']">{string[@key='version']}</xsl:when>
						<xsl:otherwise>1.0</xsl:otherwise>
					</xsl:choose>
					</xsl:attribute>
					<xsl:if test="string[@key='description']">
						<xacml:Description>{string[@key='description']}</xacml:Description>
					</xsl:if>
					<xsl:choose>
						<xsl:when test="array[@key='target']">
							<xsl:apply-templates select="array[@key='target']" />
						</xsl:when>
						<xsl:otherwise>
							<xacml:Target />
						</xsl:otherwise>
					</xsl:choose>
					<xsl:if test="array[@key='rules']">
						<xacml:Policy
							RuleCombiningAlgId="{replace(string[@key='combiningAlgId'], 'policy', 'rule')}"
							PolicyId="#generated_{generate-id(array[@key='rules'])}"
							Version="1.0">
							<xacml:Target />
							<xsl:apply-templates select="array[@key='rules']/map" />
						</xacml:Policy>
					</xsl:if>
					<xsl:apply-templates select="array[@key='policies']/map" />
				</xacml:PolicySet>
			</xsl:when>
			<xsl:otherwise>
				<xacml:Policy
					RuleCombiningAlgId="{string[@key='combiningAlgId']}"
					PolicyId="{string[@key='id']}">
					<xsl:attribute name="Version">
					<xsl:choose>
						<xsl:when test="string[@key='version']">{string[@key='version']}</xsl:when>
						<xsl:otherwise>1.0</xsl:otherwise>
					</xsl:choose>
					</xsl:attribute>
					<xsl:if test="string[@key='description']">
						<xacml:Description>{string[@key='description']}</xacml:Description>
					</xsl:if>
					<xsl:choose>
						<xsl:when test="array[@key='target']">
							<xsl:apply-templates select="array[@key='target']" />
						</xsl:when>
						<xsl:otherwise>
							<xacml:Target />
						</xsl:otherwise>
					</xsl:choose>
					<xsl:apply-templates select="array[@key='rules']/map" />
				</xacml:Policy>
			</xsl:otherwise>
		</xsl:choose>
		<!-- TODO: support MaxDelegationDepth, Advice/ObligationExpressions, (Policy)(Set)CombinerParameters, PolicyIssuer, PolicySetDefaults -->
	</xsl:template>

	<xsl:template match="map[@key='policyRef']">
		<!-- TODO: Version, EarliestVersion and LatestVersion -->
		<xacml:PolicySetIdReference>{string[@key="id"]}</xacml:PolicySetIdReference>
	</xsl:template>

</xsl:stylesheet>