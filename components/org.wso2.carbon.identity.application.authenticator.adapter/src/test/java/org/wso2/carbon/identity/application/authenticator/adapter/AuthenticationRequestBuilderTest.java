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

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.api.model.Application;
import org.wso2.carbon.identity.action.execution.api.model.Event;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.Organization;
import org.wso2.carbon.identity.action.execution.api.model.Tenant;
import org.wso2.carbon.identity.action.execution.api.model.UserClaim;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticationRequestBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.component.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticatingUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationRequestEvent;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticatedTestUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestFlowContextBuilder;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.GROUP_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.WSO2_CLAIM_DIALECT;
import static org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants;

public class AuthenticationRequestBuilderTest {

    private AuthenticationRequestBuilder authenticationRequestBuilder;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<OrganizationManagementUtil> organizationManagementUtil;
    private static final String SEPARATOR = ",";

    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = -1234;
    private static final String ORG_NAME_TEST = "subOrg";
    private static final String ORG_ID_TEST = "12345";
    private static final String USER_CLAIM_URI = WSO2_CLAIM_DIALECT + "/customUri";
    private static final String USER_CLAIM_VALUE = "customValue";
    private static final String USER_MULTI_VALUE_CLAIM_URI = WSO2_CLAIM_DIALECT + "/multiValueUri";
    private static final String USER_MULTI_CLAIM_VALUE = "value1, value2";
    private static final String USER_GROUP_VALUE = "group1, group2";
    private static final String ADDRESS = "5th Avenue, New York, USA";
    Map<String, String> headers = Map.of("header-1", "value-1", "header-2", "value-2");
    Map<String, String> parameters = Map.of("param-1", "value-1", "param-2", "value-2");
    ArrayList<AuthHistory> authHistory;

    @BeforeClass
    public void setUp() throws OrganizationManagementException {

        authHistory = TestFlowContextBuilder.buildAuthHistory();

        OrganizationManager organizationManager = mock(OrganizationManager.class);
        when(organizationManager.resolveOrganizationId(anyString())).thenReturn(ORG_ID_TEST);
        when(organizationManager.getOrganizationNameById(anyString())).thenReturn(ORG_NAME_TEST);
        AuthenticatorAdapterDataHolder.getInstance().setOrganizationManager(organizationManager);

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);
        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(SEPARATOR);

        organizationManagementUtil = mockStatic(OrganizationManagementUtil.class);
        organizationManagementUtil.when(() ->
                        OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(anyString()))
                .thenReturn(TENANT_DOMAIN_TEST);

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(() -> LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);

        authenticationRequestBuilder = new AuthenticationRequestBuilder();
    }

    @AfterClass
    public void tearDown() {

        identityTenantUtilMockedStatic.close();
        frameworkUtils.close();
        organizationManagementUtil.close();
        loggerUtils.close();
    }

    @Test
    public void testGetSupportedActionType() {

        Assert.assertEquals(authenticationRequestBuilder.getSupportedActionType(), ActionType.AUTHENTICATION);
    }

    @DataProvider
    public Object[][] flowContextDataProvider() throws UserIdNotFoundException {

        // Custom authenticator engaging in 1st step of authentication flow.
        FlowContext flowContextForNoUser = new TestFlowContextBuilder().buildFlowContext(
                 null, SUPER_TENANT_DOMAIN_NAME, headers, parameters, new ArrayList<>());

        // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
        AuthenticatedUser localUser = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                AuthenticatedUserConstants.LOCAL_USER_PREFIX, SUPER_TENANT_DOMAIN_NAME);
        FlowContext flowContextForLocalUser = new TestFlowContextBuilder().buildFlowContext(
                localUser, SUPER_TENANT_DOMAIN_NAME, headers, parameters, authHistory);

        // Custom authenticator engaging in 2nd step of authentication flow with federated authenticated user.
        AuthenticatedUser fedUser = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                AuthenticatedUserConstants.LOCAL_USER_PREFIX, SUPER_TENANT_DOMAIN_NAME);
        FlowContext flowContextForFedUser = new TestFlowContextBuilder().buildFlowContext(
                fedUser, SUPER_TENANT_DOMAIN_NAME, headers, parameters, authHistory);

        // Custom authenticator engaging in 2nd step of authentication flow with multi-value claims.
        AuthenticatedUser userWithMultiValueClaims = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                AuthenticatedUserConstants.LOCAL_USER_PREFIX, SUPER_TENANT_DOMAIN_NAME);
        userWithMultiValueClaims.setUserAttributes(buildUserAttributes());
        FlowContext flowContextForUserWithMultiValueClaims = new TestFlowContextBuilder().buildFlowContext(
                userWithMultiValueClaims, SUPER_TENANT_DOMAIN_NAME, headers, parameters, authHistory);
        AuthenticationRequestEvent expectedEventWithMultiValueClaims =
                getExpectedEvent(userWithMultiValueClaims, false);

        return new Object[][]{
                {flowContextForNoUser, getExpectedEvent(null, true), true},
                {flowContextForNoUser, getExpectedEvent(null, false), false},
                {flowContextForLocalUser, getExpectedEvent(localUser, true), true},
                {flowContextForLocalUser, getExpectedEvent(localUser, false), false},
                {flowContextForFedUser, getExpectedEvent(fedUser, true), true},
                {flowContextForFedUser, getExpectedEvent(fedUser, false), false},
                {flowContextForUserWithMultiValueClaims, expectedEventWithMultiValueClaims, false}};
    }

    @Test(dataProvider = "flowContextDataProvider")
    public void testBuildActionExecutionRequest(FlowContext flowContext, AuthenticationRequestEvent expectedEvent,
                                                boolean isSubOrgFlow) throws ActionExecutionRequestBuilderException {

        organizationManagementUtil.when(() -> OrganizationManagementUtil.isOrganization(anyString()))
                .thenReturn(isSubOrgFlow);

        ActionExecutionRequest actionExecutionRequest =
                authenticationRequestBuilder.buildActionExecutionRequest(flowContext, null);
        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getFlowId(), TestFlowContextBuilder.FLOW_ID);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.AUTHENTICATION);
        assertEvent(actionExecutionRequest.getEvent(), expectedEvent);
        assertAllowedOperations(actionExecutionRequest.getAllowedOperations());
    }

    private void assertEvent(Event actualEvent, AuthenticationRequestEvent expectedEvent) {

        Assert.assertTrue(actualEvent instanceof AuthenticationRequestEvent);
        AuthenticationRequestEvent actualAuthenticationEvent = (AuthenticationRequestEvent) actualEvent;

        Assert.assertNull(actualAuthenticationEvent.getRequest());
        Assert.assertEquals(actualAuthenticationEvent.getTenant().getId(), expectedEvent.getTenant().getId());
        Assert.assertEquals(actualAuthenticationEvent.getApplication().getId(), expectedEvent.getApplication().getId());
        Assert.assertEquals(actualAuthenticationEvent.getApplication().getName(),
                expectedEvent.getApplication().getName());

        if (expectedEvent.getUser() == null) {
            Assert.assertNull(actualAuthenticationEvent.getUser());
            Assert.assertNull(actualAuthenticationEvent.getUserStore());
            Assert.assertEquals(actualAuthenticationEvent.getCurrentStepIndex(), 1);
            Assert.assertEquals(actualAuthenticationEvent.getAuthenticatedSteps().length, 0);
            return;
        }

        Assert.assertTrue(actualAuthenticationEvent.getUser() instanceof AuthenticatingUser);
        AuthenticatingUser actualAuthenticatingUser = (AuthenticatingUser) actualAuthenticationEvent.getUser();
        AuthenticatingUser expectedUser = (AuthenticatingUser) expectedEvent.getUser();
        Assert.assertEquals(actualAuthenticatingUser.getId(), expectedUser.getId());
        Assert.assertEquals(actualAuthenticatingUser.getUserIdentitySource(), expectedUser.getUserIdentitySource());
        Assert.assertEquals(actualAuthenticatingUser.getSub(), expectedUser.getSub());
        Assert.assertEquals(actualAuthenticatingUser.getClaims().size(), expectedUser.getClaims().size());
        if (!expectedUser.getClaims().isEmpty()) {
            for (UserClaim claim : expectedUser.getClaims()) {
                boolean claimFound = false;
                for (UserClaim actualClaim : actualAuthenticatingUser.getClaims()) {
                    if (claim.getUri().equals(actualClaim.getUri())) {
                        Assert.assertEquals(actualClaim.getValue(), claim.getValue());
                        claimFound = true;
                        break;
                    }
                }
                Assert.assertTrue(claimFound);
            }
        }
        if (expectedEvent.getOrganization() == null) {
            Assert.assertNull(actualAuthenticationEvent.getOrganization());
        } else {
            Assert.assertEquals(actualAuthenticationEvent.getOrganization().getId(),
                    expectedEvent.getOrganization().getId());
            Assert.assertEquals(actualAuthenticationEvent.getOrganization().getName(),
                    expectedEvent.getOrganization().getName());
        }
        Assert.assertEquals(actualAuthenticationEvent.getUserStore().getName(), "PRIMARY");
        Assert.assertEquals(actualAuthenticationEvent.getCurrentStepIndex(), authHistory.size() + 1);
        Assert.assertEquals(actualAuthenticationEvent.getAuthenticatedSteps().length, authHistory.size());
    }

    private void assertAllowedOperations(List<AllowedOperation> allowedOperationList) {

        Assert.assertEquals(allowedOperationList.size(), 1);
        Assert.assertEquals(Operation.REDIRECT, allowedOperationList.get(0).getOp());
    }

    private AuthenticationRequestEvent getExpectedEvent(AuthenticatedUser user, boolean isSubOrgFlow)
            throws UserIdNotFoundException {

        AuthenticationRequestEvent.Builder eventBuilder = new AuthenticationRequestEvent.Builder();
        eventBuilder.tenant(new Tenant(String.valueOf(TENANT_ID_TEST), TENANT_DOMAIN_TEST));
        eventBuilder.application(new Application(TestFlowContextBuilder.SP_ID, TestFlowContextBuilder.SP_NAME));
        if (isSubOrgFlow) {
            eventBuilder.organization(new Organization(ORG_ID_TEST, ORG_NAME_TEST));
        }
        if (user != null) {
            eventBuilder.user(createAuthenticatingUser(user));
        }

        return eventBuilder.build();
    }

    private static AuthenticatingUser createAuthenticatingUser(AuthenticatedUser user) throws UserIdNotFoundException {

        AuthenticatingUser authenticatingUser = new AuthenticatingUser(user.getUserId(), user);
        if (user.isFederatedUser()) {
            authenticatingUser.setUserIdentitySource(AuthenticatorAdapterConstants.FED_IDP);
        } else {
            authenticatingUser.setUserIdentitySource(AuthenticatorAdapterConstants.LOCAL_IDP);
        }
        authenticatingUser.setSub(user.getAuthenticatedSubjectIdentifier());
        return authenticatingUser;
    }

    private static Map<ClaimMapping, String> buildUserAttributes() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        userAttributes.put(buildClaimMapping(GROUP_CLAIM), USER_GROUP_VALUE);
        userAttributes.put(buildClaimMapping(ADDRESS_CLAIM), ADDRESS);
        userAttributes.put(buildClaimMapping(USER_MULTI_VALUE_CLAIM_URI), USER_MULTI_CLAIM_VALUE);
        userAttributes.put(buildClaimMapping(USER_CLAIM_URI), USER_CLAIM_VALUE);
        return userAttributes;
    }

    private static ClaimMapping buildClaimMapping(String claimUri) {

        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri(claimUri);
        claimMapping.setRemoteClaim(claim);
        claimMapping.setLocalClaim(claim);
        return claimMapping;
    }
}
