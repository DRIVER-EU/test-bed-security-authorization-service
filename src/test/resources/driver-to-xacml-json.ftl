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
						[
							[
								<#list driverAccessRule.subjectMatches as attributeId, attributeValue>
									{
										"matchFunction": "urn:oasis:names:tc:xacml:1.0:function:string-equal",
										"value": "${attributeValue}",
										"attributeDesignator": {
											"category": "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
											"id": "<#switch attributeId>
											<#case "subject.id">urn:oasis:names:tc:xacml:1.0:subject:subject-id<#break>
									  		<#case "subject.group">urn:thalesgroup:xacml:group-id<#break>
									  		<#default>${attributeId}<#break>
											</#switch>",
											"dataType": "http://www.w3.org/2001/XMLSchema#string",
											"mustBePresent": false
										}
									}
									<#sep>,</#sep>
								</#list>
							]
						]
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