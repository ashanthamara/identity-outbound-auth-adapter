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

package org.wso2.carbon.identity.application.authenticator.adapter.util;

import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionResponseContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationFailureResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationIncompleteResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.api.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.api.model.ResponseData;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticatedUserData;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationRequestEvent;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticationAdapterConstants.AuthenticatingUserConstants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticationAdapterConstants.AuthenticatingUserConstants.ADDRESS_CLAIM;

public class TestActionInvocationResponseBuilder {

    private static AuthenticationRequestEvent authenticationRequestEvent;

    /**
     * Build an action invocation error response.
     *
     * @return ActionInvocationResponse
     */
    public static ActionExecutionResponseContext<ActionInvocationErrorResponse> buildActionInvocationErrorResponse() {

        return ActionExecutionResponseContext.create(authenticationRequestEvent,
                new ActionInvocationErrorResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.ERROR)
                .errorMessage("error-1")
                .errorDescription("error description").build());
    }

    /**
     * Build an action invocation failure response.
     *
     * @return ActionInvocationResponse
     */
    public static ActionExecutionResponseContext<ActionInvocationFailureResponse>
    buildActionInvocationFailureResponse() {

        return ActionExecutionResponseContext.create(authenticationRequestEvent,
                new ActionInvocationFailureResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.FAILED)
                .failureReason("failure-1")
                .failureDescription("failure description").build());
    }

    /**
     * Build an action invocation success response for success authentication with external service.
     *
     * @return ActionInvocationResponse
     */
    public static ActionExecutionResponseContext<ActionInvocationSuccessResponse> buildAuthenticationSuccessResponse(
            List<PerformableOperation> operations, ResponseData data) {

        return ActionExecutionResponseContext.create(authenticationRequestEvent,
                new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operations)
                .responseData(data)
                .build());
    }

    /**
     * Build an action invocation success response for redirection.
     *
     * @return ActionInvocationResponse
     */
    public static ActionExecutionResponseContext<ActionInvocationIncompleteResponse>
    buildAuthenticationRedirectResponse(List<PerformableOperation> operations) {

        return ActionExecutionResponseContext.create(authenticationRequestEvent,
                new ActionInvocationIncompleteResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.INCOMPLETE)
                .operations(operations)
                .build());
    }

    public static class ExternallyAuthenticatedUser extends AuthenticatedUserData.User {

        AuthenticatedUserData.Claim  userNameClaim = new AuthenticatedUserData.Claim(
                AuthenticatorAdapterConstants.USERNAME_CLAIM, AuthenticatingUserConstants.USERNAME);

        private String id;
        private List<String> groups;
        private List<AuthenticatedUserData.Claim> claims;
        private AuthenticatedUserData.UserStore userStore;

        public ExternallyAuthenticatedUser() {

            id = AuthenticatingUserConstants.USERID;
            userStore = new AuthenticatedUserData.UserStore(
                    AuthenticatingUserConstants.USER_STORE_ID, AuthenticatingUserConstants.USER_STORE_NAME);
            groups = new ArrayList<>();
            claims = buildUserClaims();
        }

        public void setId(String id) {

            this.id = id;
        }

        public void setGroups(List<String> groups) {

            this.groups = groups;
        }

        public void setClaims(List<AuthenticatedUserData.Claim> claims) {

            this.claims = claims;
        }

        public String getId() {

            return id;
        }

        public List<String> getGroups() {

            return groups;
        }

        public List<AuthenticatedUserData.Claim> getClaims() {

            return claims;
        }

        public void setUserStore(AuthenticatedUserData.UserStore userStore) {

            this.userStore = userStore;
        }

        public AuthenticatedUserData.UserStore getUserStore() {

            return userStore;
        }

        public void setUserName(String userName) {

            claims.removeIf(claim -> AuthenticatorAdapterConstants.USERNAME_CLAIM.equals(claim.getUri()));
            claims.add(new AuthenticatedUserData.Claim(AuthenticatorAdapterConstants.USERNAME_CLAIM, userName));
        }

        private ArrayList<AuthenticatedUserData.Claim> buildUserClaims() {

            return new ArrayList<>(List.of(
                    userNameClaim,
                    new AuthenticatedUserData.Claim(ADDRESS_CLAIM, AuthenticatingUserConstants.ADDRESS),
                    new AuthenticatedUserData.Claim(
                            AuthenticatingUserConstants.USER_CLAIM_URI, AuthenticatingUserConstants.USER_CLAIM_VALUE),
                    new AuthenticatedUserData.Claim(AuthenticatingUserConstants.USER_MULTI_VALUE_CLAIM_URI,
                            Arrays.asList(AuthenticatingUserConstants.USER_MULTI_CLAIM_VALUE
                                    .split(AuthenticatingUserConstants.SEPARATOR)))));
        }
    }
}
