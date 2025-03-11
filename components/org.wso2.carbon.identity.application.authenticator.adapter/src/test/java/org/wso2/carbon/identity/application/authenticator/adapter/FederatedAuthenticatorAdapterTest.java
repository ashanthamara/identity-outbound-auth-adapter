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

package org.wso2.carbon.identity.application.authenticator.adapter;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.IncompleteStatus;
import org.wso2.carbon.identity.action.execution.api.model.SuccessStatus;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutorService;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.api.UserDefinedFederatedAuthenticator;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.component.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticatedTestUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticationAdapterConstants.AuthenticatingUserConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestFlowContextBuilder;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.UserDefinedFederatedAuthenticatorConfig;

import java.util.ArrayList;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Unit tests for UserDefinedFederatedAuthenticator.
 */
public class FederatedAuthenticatorAdapterTest {

    private static final String AUTHENTICATOR_NAME = "UserDefinedFederatedAuthenticator";
    private UserDefinedFederatedAuthenticator userDefinedFederatedAuthenticator;

    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private AuthenticationContext authContextWithNoUser;
    private AuthenticationContext authContextWithLocalUserFromFirstStep;
    private AuthenticationContext authContextWithFedUserFromFirstStep;
    private AuthenticatedUser localAuthenticatedUser;
    private AuthenticatedUser federatedAuthenticatedUser;
    private AuthenticatedUser expectedAuthenticatedUser;
    private ActionExecutorService mockedActionExecutorService;
    private static ArrayList<AuthHistory> authHistory;

    @BeforeClass
    public void setUp() {

        UserDefinedFederatedAuthenticatorConfig fedConfig = new UserDefinedFederatedAuthenticatorConfig();
        fedConfig.setName(AUTHENTICATOR_NAME);
        userDefinedFederatedAuthenticator = new UserDefinedFederatedAuthenticator(fedConfig);

        mockedActionExecutorService = mock(ActionExecutorService.class);
        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(mockedActionExecutorService);

        authHistory = TestFlowContextBuilder.buildAuthHistory();
        buildEventContext();

        expectedAuthenticatedUser = new AuthenticatedUser();
        expectedAuthenticatedUser.setUserId(AuthenticatingUserConstants.USERID);
        expectedAuthenticatedUser.setUserStoreDomain(AuthenticatingUserConstants.USER_STORE_NAME);
        expectedAuthenticatedUser.setUserName(AuthenticatingUserConstants.USERNAME);
        expectedAuthenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
    }

    @Test
    public void testGetFriendlyName() {

        Assert.assertEquals(userDefinedFederatedAuthenticator.getFriendlyName(), AUTHENTICATOR_NAME);
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(userDefinedFederatedAuthenticator.getName(), AUTHENTICATOR_NAME);
    }

    @Test
    public void testClaimDialectURI() {

        Assert.assertEquals(userDefinedFederatedAuthenticator.getClaimDialectURI(),
                AuthenticatorAdapterConstants.WSO2_CLAIM_DIALECT);
    }

    @DataProvider
    public Object[][] provideAuthenticationContext() {

        return new Object[][]{
                {authContextWithNoUser, 1},
                {authContextWithLocalUserFromFirstStep, 2},
                {authContextWithFedUserFromFirstStep, 2}
        };
    }

    @Test(dataProvider = "provideAuthenticationContext")
    public void testSuccessAuthenticationRequestProcess(AuthenticationContext context, int currentStep)
            throws Exception {

        when(mockedActionExecutorService.execute(any(), any(), any(FlowContext.class), any()))
                .thenAnswer(invocation -> {
            context.setSubject(expectedAuthenticatedUser);
            return new SuccessStatus.Builder().setResponseContext(new HashMap<>()).build();
        });
        context.setCurrentStep(currentStep);
        AuthenticatorFlowStatus authStatus = userDefinedFederatedAuthenticator.process(request, response, context);

        Assert.assertEquals(authStatus, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(dataProvider = "provideAuthenticationContext")
    public void testIncompleteAuthenticationRequestProcess(AuthenticationContext context, int currentStep)
            throws Exception {

        when(mockedActionExecutorService.execute(any(), any(), any(FlowContext.class), any())).thenReturn(
                new IncompleteStatus.Builder().responseContext(new HashMap<>()).build());
        context.setCurrentStep(currentStep);
        AuthenticatorFlowStatus authStatus = userDefinedFederatedAuthenticator.process(request, response, context);

        Assert.assertEquals(authStatus, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertEquals(context.getCurrentAuthenticator(), AUTHENTICATOR_NAME);
        Assert.assertFalse(context.isRetrying());
    }

    public void buildEventContext() {

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName("testIdp");

        // Custom authenticator engaging in 1st step of authentication flow.
        authContextWithNoUser = new TestFlowContextBuilder().buildAuthenticationContext(
                null, SUPER_TENANT_DOMAIN_NAME, new ArrayList<AuthHistory>());
        authContextWithNoUser.setExternalIdP(new ExternalIdPConfig(idp));

        // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
        localAuthenticatedUser = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants.LOCAL_USER_PREFIX,
                SUPER_TENANT_DOMAIN_NAME);
        authContextWithLocalUserFromFirstStep = new TestFlowContextBuilder().buildAuthenticationContext(
                localAuthenticatedUser, SUPER_TENANT_DOMAIN_NAME, authHistory);
        authContextWithLocalUserFromFirstStep.setExternalIdP(new ExternalIdPConfig(idp));

        // Custom authenticator engaging in 2nd step of authentication flow with federated authenticated user.
        federatedAuthenticatedUser = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants.LOCAL_USER_PREFIX,
                SUPER_TENANT_DOMAIN_NAME);
        authContextWithFedUserFromFirstStep = new TestFlowContextBuilder().buildAuthenticationContext(
                federatedAuthenticatedUser, SUPER_TENANT_DOMAIN_NAME, authHistory);
        authContextWithFedUserFromFirstStep.setExternalIdP(new ExternalIdPConfig(idp));
    }
}
