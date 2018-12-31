/**
 * Copyright (C) 2012-2018 THALES.
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

import java.util.Optional;

import org.json.JSONObject;
import org.ow2.authzforce.core.pdp.api.policy.PolicyVersion;

interface PrpDao
{
	/**
	 * Creates a transaction - ACID transaction - to handle rollback in case of error during a procedure involving changes to the PRP (database)
	 * 
	 * @return new transaction handler
	 * 
	 */
	Transaction newTx();

	void addPolicyVersion(Transaction tx, String policyId, String policyVersion, JSONObject policyContent, Optional<String> customPolicyContentTypeId);

	/**
	 * Get latest version of a given policy
	 * 
	 * @param policyId
	 *            policy identifier
	 * @return policy version or none (Optional.empty()) if there is not any version of the policy in the PRP (policy not found)
	 */
	Optional<PolicyVersion> getLatestPolicyVersion(String policyId);

	/**
	 * Gets the content of a given policy
	 * 
	 * @param policyId
	 *            policy identifier
	 * @param policyVersion
	 *            policy content version
	 * @return policy content (JSON); {@link Optional#empty()} if policy not found
	 */
	Optional<JSONObject> getPolicy(String policyId, Optional<PolicyVersion> policyVersion);

	Optional<JSONObject> getLatestPolicyVersionContent(String policyId, Optional<String> customPolicyContentTypeId);

	void deletePolicy(Transaction tx, String policyId);
}