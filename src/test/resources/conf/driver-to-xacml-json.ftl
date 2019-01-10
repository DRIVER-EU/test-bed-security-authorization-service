{
		"id": "${id}",
		"version": "${version}",
		"target": [
			[
				[
					{
						"matchFunction": "urn:oasis:names:tc:xacml:1.0:function:string-equal",
						"value": "${targetValue}",
						"attributeDesignator": {
							"category": "urn:oasis:names:tc:xacml:3.0:attribute-category:resource",
							"id": "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
							"dataType": "http://www.w3.org/2001/XMLSchema#string",
							"mustBePresent": true
						}
					}
				]
			]
		],
		"combiningAlgId": "urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:first-applicable",
		"policies": [
           <#list driverAccessRules as driverAccessRule>
			{
				"policy": {
				    <#assign subjectMatchPresent = driverAccessRule.subjectMatches?size != 0 >
					"id": "<#if subjectMatchPresent><#list driverAccessRule.subjectMatches as attributeId, attributeValue>${attributeId}=${attributeValue}<#sep> AND </#sep></#list><#else>ANY_SUBJECT</#if>",
					"version": "1.0",
					<#if subjectMatchPresent>
					"target": [
						<#list driverAccessRule.subjectMatches as attributeId, attributeValue>
						[
							[
								
								{
									"value": "${attributeValue}",
									"attributeDesignator": {
										"category": "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
										<#switch attributeId>
											<#case "subject.id">
										"id": "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
										"dataType": "urn:oasis:names:tc:xacml:1.0:data-type:x500Name",
										"mustBePresent": false
									},
									"matchFunction": "urn:oasis:names:tc:xacml:1.0:function:x500Name-equal"
								}
							],
							[
								{
								<#-- subject.id is a certificate subject DN that may be in LDAP DN order or X.500 order (reverse). We must support both. -->
									value": "${attributeValue?split(",")?reverse?join(",")}",
									"attributeDesignator": {
										"category": "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
										"id": "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
										"dataType": "urn:oasis:names:tc:xacml:1.0:data-type:x500Name",
										"mustBePresent": false
									},
									"matchFunction": "urn:oasis:names:tc:xacml:1.0:function:x500Name-equal"
											<#break>
									  		<#case "subject.group">
										"id":"urn:thalesgroup:xacml:group-id",
										"dataType": "http://www.w3.org/2001/XMLSchema#string",
										"mustBePresent": false
									},
									"matchFunction": "urn:oasis:names:tc:xacml:1.0:function:string-equal"
									  		<#break>
									  		<#default>
							  			"id": "${attributeId}",
							  			"dataType": "http://www.w3.org/2001/XMLSchema#string",
							  			"mustBePresent": false
							  		},
							  		"matchFunction": "urn:oasis:names:tc:xacml:1.0:function:string-equal"
									  		<#break>
										</#switch>
								}
							]
						]
							<#sep>,</#sep>
						</#list>
					],
					</#if>
					"combiningAlgId": "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable",
					"rules": [
                       <#list driverAccessRule.permissions as driverPerm>
	                        <#assign kafkaOperationId>
								  <#switch driverPerm.action>
									  <#case "SUBSCRIBE">READ<#break>
									  <#case "PUBLISH">WRITE<#break>
									  <#default>${driverPerm.action}<#break>
									</#switch>
							</#assign>
							{
								"id": "action.id=${driverPerm.action}",
								"effect": "${driverPerm.allow?then('Permit', 'Deny')}",
								"target": [
									[
										[
											{
												"matchFunction": "urn:oasis:names:tc:xacml:1.0:function:string-equal",
												"value": "${kafkaOperationId}",
												"attributeDesignator": {
													"category": "urn:oasis:names:tc:xacml:3.0:attribute-category:action",
													"id": "urn:oasis:names:tc:xacml:1.0:action:action-id",
													"dataType": "http://www.w3.org/2001/XMLSchema#string",
													"mustBePresent": true
												}
											}
										]
									]
								]
							}
	                        <#sep>,</#sep>
						</#list>
					]
				}
			}
            <#sep>,</#sep>
           </#list>
		]
}