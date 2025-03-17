/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *X
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.adapter.util;

import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.WSO2_CLAIM_DIALECT;

/**
 * This class holds the constants related to the authentication adapter.
 */
public class TestAuthenticationAdapterConstants {

    public static class AuthenticatingUserConstants {

        public static final String USERID = "default-id";
        public static final String USER_STORE_NAME = "testUserStore";
        public static final String USER_STORE_ID = "userStoreId";
        public static final String USERNAME = "TestUser";
        public static final String USER_CLAIM_URI = WSO2_CLAIM_DIALECT + "/customUri";
        public static final String USER_CLAIM_VALUE = "customValue";
        public static final String USER_MULTI_VALUE_CLAIM_URI = WSO2_CLAIM_DIALECT + "/multiValueUri";
        public static final String USER_MULTI_CLAIM_VALUE = "value1, value2";
        public static final String ADDRESS = "5th Avenue, New York, USA";
        public static final String SEPARATOR = ",";
        public static final String ADDRESS_CLAIM = "http://wso2.org/claims/addresses";
    }

}
