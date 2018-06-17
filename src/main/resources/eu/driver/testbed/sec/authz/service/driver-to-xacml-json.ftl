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
           <#list driverAcrs as driverAcr>
			{
				"policy": {
					"id": "subject.id=${driverAcr.subject}",
					"version": "1.0",
					"target": [
						[
							[
								{
									"matchFunction": "urn:oasis:names:tc:xacml:1.0:function:string-equal",
									"value": "${driverAcr.subject}",
									"attributeDesignator": {
										"category": "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
										"id": "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
										"dataType": "http://www.w3.org/2001/XMLSchema#string",
										"mustBePresent": true
									}
								}
							]
						]
					],
					"combiningAlgId": "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable",
					"rules": [
                       <#list driverAcr.permissions as driverPerm>
                        <#assign kafkaOperationId>
							  <#switch driverPerm.action>
								  <#case "SUBSCRIBE">READ<#break>
								  <#case "PUBLISH">WRITE<#break>
								  <#default>${driverPerm.action}
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