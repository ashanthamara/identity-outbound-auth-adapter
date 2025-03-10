/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.adapter.internal.model;

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.action.execution.api.model.User;
import org.wso2.carbon.identity.action.execution.api.model.UserClaim;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.MULTI_ATTR_SEPARATOR;

/**
 * This class holds the authenticated user object which is communicated to the external authentication service.
 */
public class AuthenticatingUser extends User {

    private String userIdentitySource;
    private String sub;
    private final List<UserClaim> claims = new ArrayList<>();

    public static final String ADDRESS = "address";
    public static final String GROUPS = "groups";

    public AuthenticatingUser(String id) {
        super(id);
    }

    public AuthenticatingUser(String id, AuthenticatedUser user) {
        super(id);
        sub = user.getAuthenticatedSubjectIdentifier();
        userIdentitySource = user.isFederatedUser() ?
                AuthenticatorAdapterConstants.FED_IDP : AuthenticatorAdapterConstants.LOCAL_IDP;

        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
        if (userAttributes != null) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                String claimUri = entry.getKey().getLocalClaim().getClaimUri();
                String claimValue = entry.getValue();
                if (isMultiValuedAttribute(claimUri, claimValue)) {
                    String[] attributeValues = claimValue.split(Pattern.quote(MULTI_ATTR_SEPARATOR));
                    claims.add(new UserClaim(claimUri, attributeValues));
                    continue;
                }
                claims.add(new UserClaim(claimUri, claimValue));
            }
        }
    }

    public List<UserClaim> getClaims() {
        return claims;
    }

    public void setUserIdentitySource(String userIdentitySource) {
        this.userIdentitySource = userIdentitySource;
    }

    public String getUserIdentitySource() {
        return userIdentitySource;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getSub() {
        return sub;
    }

    private boolean isMultiValuedAttribute(String claimKey, String claimValue) {

        // Address claim contains multi attribute separator but its not a multi valued attribute.
        if (claimKey.equals(ADDRESS)) {
            return false;
        }
        // To format the groups claim to always return as an array, we should consider single group as
        // multi value attribute.
        if (claimKey.equals(GROUPS)) {
            return true;
        }
        return StringUtils.contains(claimValue, MULTI_ATTR_SEPARATOR);
    }
}

