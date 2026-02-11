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

package org.wso2.carbon.identity.application.authenticator.adapter.internal;

import org.osgi.annotation.bundle.Capability;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.UserDefinedAuthenticatorService;
import org.wso2.carbon.identity.application.authenticator.adapter.api.UserDefinedFederatedAuthenticator;
import org.wso2.carbon.identity.application.authenticator.adapter.api.UserDefinedLocalAuthenticator;
import org.wso2.carbon.identity.application.common.model.UserDefinedFederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.UserDefinedLocalAuthenticatorConfig;

/**
 * This is the UserDefinedAuthenticatorService implementation class to create ApplicationAuthenticator instance
 * for the give application authenticator configuration.
 */
@Capability(
        namespace = "osgi.service",
        attribute = {
                "objectClass=org.wso2.carbon.identity.application.authentication.framework" +
                        ".UserDefinedAuthenticatorService",
                "service.scope=singleton"
        }
)
public class UserDefinedAuthenticatorServiceImpl implements UserDefinedAuthenticatorService {

    /**
     * Provide new FederatedApplicationAuthenticator for given federated authenticator configuration.
     *
     * @param config    User Defined Federated Authenticator Configuration.
     * @return  UserDefinedFederatedAuthenticator instance.
     */
    @Override
    public FederatedApplicationAuthenticator getUserDefinedFederatedAuthenticator(
            UserDefinedFederatedAuthenticatorConfig config) {

        return new UserDefinedFederatedAuthenticator(config);
    }

    /**
     * Provide new LocalApplicationAuthenticator for given local authenticator configuration.
     *
     * @param config    User Defined Local Authenticator Configuration.
     * @return  UserDefinedLocalAuthenticator instance.
     */
    @Override
    public LocalApplicationAuthenticator getUserDefinedLocalAuthenticator(UserDefinedLocalAuthenticatorConfig config) {

        return new UserDefinedLocalAuthenticator(config);
    }
}
