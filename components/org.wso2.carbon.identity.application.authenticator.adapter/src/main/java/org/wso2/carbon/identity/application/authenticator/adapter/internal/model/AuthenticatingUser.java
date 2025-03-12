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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.ADDRESS_CLAIM;

/**
 * This class holds the authenticated user object which is communicated to the external authentication service.
 */
public class AuthenticatingUser extends User {

    private String userIdentitySource;
    private String sub;

    public AuthenticatingUser(String id, AuthenticatedUser user) {

        super(buildUser(id, user));
        sub = user.getAuthenticatedSubjectIdentifier();
        userIdentitySource = user.isFederatedUser() ?
                AuthenticatorAdapterConstants.FED_IDP : AuthenticatorAdapterConstants.LOCAL_IDP;
    }

    private static User.Builder buildUser(String id, AuthenticatedUser user) {

        User.Builder userBuilder = new User.Builder(id);
        String multiAttributeSeparator = FrameworkUtils.getMultiAttributeSeparator();

        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
        List<UserClaim> userClaimList = new ArrayList<>();
        if (userAttributes != null) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                String claimUri = entry.getKey().getLocalClaim().getClaimUri();
                if (claimUri.equals(AuthenticatorAdapterConstants.GROUP_CLAIM)) {
                    userBuilder.groups(Arrays.asList(entry.getValue().split(Pattern.quote(multiAttributeSeparator))));
                    continue;
                } else if (claimUri.equals(AuthenticatorAdapterConstants.ROLES_CLAIM)) {
                    /* Since we are not supporting role management with the custom authenticator in the initial phase,
                     we are ignoring it. */
                    continue;
                }

                String claimValue = entry.getValue();
                if (isMultiValuedAttribute(claimUri, claimValue, multiAttributeSeparator)) {
                    String[] attributeValues = claimValue.split(Pattern.quote(multiAttributeSeparator));
                    userClaimList.add(new UserClaim(claimUri, attributeValues));
                    continue;
                }
                userClaimList.add(new UserClaim(claimUri, claimValue));
            }
        }
        userBuilder.claims(userClaimList);
        return userBuilder;
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

    private static boolean isMultiValuedAttribute(String claimKey, String claimValue, String multiAttributeSeparator) {

        // Address claim contains multi attribute separator but its not a multi valued attribute.
        if (claimKey.equals(ADDRESS_CLAIM)) {
            return false;
        }
        return StringUtils.contains(claimValue, multiAttributeSeparator);
    }
}

