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

package org.wso2.carbon.identity.application.authenticator.adapter.internal.constant;

/**
 * This class holds the constants related to the authentication adapter.
 */
public class AuthenticatorAdapterConstants {

    public static final String AUTHENTICATOR_NAME = "AbstractAuthenticatorAdapter";
    public static final String WSO2_CLAIM_DIALECT = "http://wso2.org/claims";
    public static final String EXTERNAL_ID_CLAIM = "http://wso2.org/claims/externalid";
    public static final String USERNAME_CLAIM = "http://wso2.org/claims/username";
    public static final String GROUP_CLAIM = "http://wso2.org/claims/groups";
    public static final String ROLES_CLAIM = "http://wso2.org/claims/roles";
    public static final String AUTH_REQUEST = "authenticationRequest";
    public static final String AUTH_RESPONSE = "authenticationResponse";
    public static final String AUTH_CONTEXT = "authContext";
    public static final String AUTH_TYPE = "authenticatorType";
    public static final String AUTHENTICATOR_NAME_PROP = "authenticatorName";
    public static final String FLOW_ID = "flowId";
    public static final String ACTION_ID_CONFIG = "actionId";;
    public static final String LOCAL_IDP = "LOCAL";
    public static final String FED_IDP = "FEDERATED";
    public static final String EXECUTION_STATUS_PROP_NAME = "actionExecutionStatus";
    public static final String PARAM_STATE = "state";
    public static final String PARAM_ENDPOINT_URL = "endpointUrl";
    public static final String STATE_PARAM_SUFFIX = "_state_param";
    public static final String ENDPOINT_URL_SUFFIX = "_endpointUrl_param";

    public static final String DEFAULT_USER_STORE_CONFIG_PATH = "Actions.Types.Authentication.DefaultUserStore";

    /**
     * User Type of the authenticated user communicated with the external authentication service.
     */
    public enum UserType {
        LOCAL,
        FEDERATED
    }
}
