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
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.api.model.Application;
import org.wso2.carbon.identity.action.execution.api.model.Event;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Header;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.Organization;
import org.wso2.carbon.identity.action.execution.api.model.Param;
import org.wso2.carbon.identity.action.execution.api.model.Request;
import org.wso2.carbon.identity.action.execution.api.model.Tenant;
import org.wso2.carbon.identity.action.execution.api.model.UserClaim;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticationRequestBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.component.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticatingUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationRequestEvent;
import org.wso2.carbon.identity.application.authenticator.adapter.util.MockServiceBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticatedTestUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestFlowContextBuilder;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.GROUP_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.WSO2_CLAIM_DIALECT;
import static org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants;
import static org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticationAdapterConstants.AuthenticatingUserConstants.ADDRESS_CLAIM;

@WithCarbonHome
public class AuthenticationRequestBuilderTest {

    private AuthenticationRequestBuilder authenticationRequestBuilder;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<OrganizationManagementUtil> organizationManagementUtil;
    private OrganizationManager organizationManager;
    private AuthenticatedUser localUser;
    private AuthenticatedUser fedUser;
    private AuthenticatedUser userWithMultiValueClaims;
    private static final String SEPARATOR = ",";

    private static final String ROOT_ORG_ID_TEST = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = -1234;
    private static final String ORG_NAME_TEST = "subOrg";
    private static final String ORG_HANDLE_TEST = "subOrg.com";
    private static final String ORG_ID_TEST = "550e8400-e29b-41d4-a716-446655440000";
    private static final int ORG_DEPTH_TEST = 1;
    private static final String USER_CLAIM_URI = WSO2_CLAIM_DIALECT + "/customUri";
    private static final String USER_CLAIM_VALUE = "customValue";
    private static final String USER_MULTI_VALUE_CLAIM_URI = WSO2_CLAIM_DIALECT + "/multiValueUri";
    private static final String USER_MULTI_CLAIM_VALUE = "value1, value2";
    private static final String USER_GROUP_VALUE = "group1, group2";
    private static final String ADDRESS = "5th Avenue, New York, USA";
    private static Map<ClaimMapping, String> userAttributes;
    Map<String, String> headers = Map.of("header-1", "value-1", "header-2", "value-2");
    Map<String, String> parameters = Map.of("param-1", "value-1", "param-2", "value-2");
    ArrayList<AuthHistory> authHistory;

    @BeforeClass
    public void setUp() throws Exception {

        authHistory = TestFlowContextBuilder.buildAuthHistory();

        organizationManager = mock(OrganizationManager.class);
        AuthenticatorAdapterDataHolder.getInstance().setOrganizationManager(organizationManager);

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);
        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(SEPARATOR);

        organizationManagementUtil = mockStatic(OrganizationManagementUtil.class);

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        authenticationRequestBuilder = new AuthenticationRequestBuilder();
        userAttributes = buildUserAttributes();
        AuthenticatorAdapterDataHolder.getInstance().setClaimManagementService(
                MockServiceBuilder.mockClaimMetadataManagementService(
                        new ArrayList<>(userAttributes.keySet()), TENANT_DOMAIN_TEST));

        localUser = TestAuthenticatedTestUserBuilder
                .createAuthenticatedUser(AuthenticatedUserConstants.LOCAL_USER_PREFIX, SUPER_TENANT_DOMAIN_NAME);
        fedUser = TestAuthenticatedTestUserBuilder
                .createAuthenticatedUser(AuthenticatedUserConstants.LOCAL_USER_PREFIX, SUPER_TENANT_DOMAIN_NAME);
        userWithMultiValueClaims = TestAuthenticatedTestUserBuilder
                .createAuthenticatedUser(AuthenticatedUserConstants.LOCAL_USER_PREFIX, SUPER_TENANT_DOMAIN_NAME);
        userWithMultiValueClaims.setUserAttributes(userAttributes);
    }

    @AfterClass
    public void tearDown() {

        identityTenantUtilMockedStatic.close();
        frameworkUtils.close();
        organizationManagementUtil.close();
        loggerUtils.close();
    }

    @AfterMethod
    public void end() {

        IdentityContext.destroyCurrentContext();
    }

    @Test
    public void testGetSupportedActionType() {

        Assert.assertEquals(authenticationRequestBuilder.getSupportedActionType(), ActionType.AUTHENTICATION);
    }

    private FlowContext getFlowContextForNoUser(String tenantDomain) {

        return new TestFlowContextBuilder().buildFlowContext(
                null, tenantDomain, headers, parameters, new ArrayList<>());
    }

    private FlowContext getFlowContextForUser(AuthenticatedUser user, String tenantDomain) {

        return new TestFlowContextBuilder().buildFlowContext(
                user, tenantDomain, headers, parameters, authHistory);
    }

    @DataProvider
    public Object[][] requestBuilderDataProvider() {

        return new Object[][]{
                // Custom authenticator engaging in 1st step of authentication flow.
                {getFlowContextForNoUser(TENANT_DOMAIN_TEST), null},
                // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
                {getFlowContextForUser(localUser, TENANT_DOMAIN_TEST), localUser},
                // Custom authenticator engaging in 2nd step of authentication flow with federated authenticated user.
                {getFlowContextForUser(fedUser, TENANT_DOMAIN_TEST), fedUser},
                // Custom authenticator engaging in 2nd step of authentication flow with multi-value claims.
                {getFlowContextForUser(userWithMultiValueClaims, TENANT_DOMAIN_TEST), userWithMultiValueClaims}};
    }

    @Test(dataProvider = "requestBuilderDataProvider")
    public void testBuildActionExecutionRequest(FlowContext flowContext, AuthenticatedUser user) throws Exception {

        AuthenticationRequestEvent expectedEvent = getExpectedEvent(user, false);
        IdentityContext.getThreadLocalIdentityContext().setRootOrganization(new RootOrganization.Builder()
                .organizationId(ROOT_ORG_ID_TEST)
                .associatedTenantDomain(TENANT_DOMAIN_TEST)
                .associatedTenantId(TENANT_ID_TEST)
                .build());
        IdentityContext.getThreadLocalIdentityContext().setOrganization(
                new org.wso2.carbon.identity.core.context.model.Organization.Builder()
                    .id(ROOT_ORG_ID_TEST)
                    .name(TENANT_DOMAIN_TEST)
                    .organizationHandle(TENANT_DOMAIN_TEST)
                    .depth(0)
                    .build());

        ActionExecutionRequest actionExecutionRequest =
                authenticationRequestBuilder.buildActionExecutionRequest(flowContext, null);
        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getFlowId(), TestFlowContextBuilder.FLOW_ID);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.AUTHENTICATION);
        assertEvent(actionExecutionRequest.getEvent(), expectedEvent);
        assertAllowedOperations(actionExecutionRequest.getAllowedOperations());
    }

    @DataProvider
    public Object[][] requestBuilderSubOrgDataProvider() {

        return new Object[][]{
                // Custom authenticator engaging in 1st step of authentication flow.
                {getFlowContextForNoUser(ORG_HANDLE_TEST), null},
                // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
                {getFlowContextForUser(localUser, ORG_HANDLE_TEST), localUser},
                // Custom authenticator engaging in 2nd step of authentication flow with federated authenticated user.
                {getFlowContextForUser(fedUser, ORG_HANDLE_TEST), fedUser},
                // Custom authenticator engaging in 2nd step of authentication flow with multi-value claims.
                {getFlowContextForUser(userWithMultiValueClaims, ORG_HANDLE_TEST), userWithMultiValueClaims}};
    }

    @Test(dataProvider = "requestBuilderSubOrgDataProvider")
    public void testBuildActionExecutionRequestForSubOrg(FlowContext flowContext, AuthenticatedUser user)
            throws Exception {

        AuthenticationRequestEvent expectedEvent = getExpectedEvent(user, true);
        IdentityContext.getThreadLocalIdentityContext().setRootOrganization(new RootOrganization.Builder()
                .organizationId(ROOT_ORG_ID_TEST)
                .associatedTenantDomain(TENANT_DOMAIN_TEST)
                .associatedTenantId(TENANT_ID_TEST)
                .build());
        IdentityContext.getThreadLocalIdentityContext().setOrganization(
                new org.wso2.carbon.identity.core.context.model.Organization.Builder()
                        .id(ORG_ID_TEST)
                        .name(ORG_NAME_TEST)
                        .organizationHandle(ORG_HANDLE_TEST)
                        .depth(ORG_DEPTH_TEST)
                        .build());

        ActionExecutionRequest actionExecutionRequest =
                authenticationRequestBuilder.buildActionExecutionRequest(flowContext, null);
        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getFlowId(), TestFlowContextBuilder.FLOW_ID);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.AUTHENTICATION);
        assertEvent(actionExecutionRequest.getEvent(), expectedEvent);
        assertAllowedOperations(actionExecutionRequest.getAllowedOperations());
    }


    @Test(dataProvider = "requestBuilderSubOrgDataProvider")
    public void testBuildActionExecutionRequestWithResolvingOrgInternally(FlowContext flowContext,
                                                                          AuthenticatedUser user) throws Exception {

        AuthenticationRequestEvent expectedEvent = getExpectedEvent(user, true);
        when(organizationManager.resolveOrganizationId(anyString())).thenReturn(ORG_ID_TEST);
        when(organizationManager.getMinimalOrganization(anyString(), anyString())).thenReturn(
                new MinimalOrganization.Builder()
                        .id(ORG_ID_TEST)
                        .name(ORG_NAME_TEST)
                        .organizationHandle(ORG_HANDLE_TEST)
                        .depth(ORG_DEPTH_TEST)
                        .build());
        when(organizationManager.getOrganizationNameById(anyString())).thenReturn(ORG_NAME_TEST);
        organizationManagementUtil.when(() ->
                        OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(anyString()))
                .thenReturn(TENANT_DOMAIN_TEST);

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

        assertRequest(actualAuthenticationEvent.getRequest(), expectedEvent.getRequest());
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

    private void assertRequest(Request actualRequest, Request expectedRequest) {

        Assert.assertTrue(actualRequest instanceof AuthenticationRequest);
        AuthenticationRequest actualAuthRequest = (AuthenticationRequest) actualRequest;

        Assert.assertEquals(actualAuthRequest.getAdditionalHeaders().size(), this.headers.size());
        Assert.assertEquals(actualAuthRequest.getAdditionalParams().size(), this.parameters.size());
        for (Header expectedHeader : expectedRequest.getAdditionalHeaders()) {
            Header actualHeader = actualAuthRequest.getAdditionalHeaders().stream()
                    .filter(h -> h.getName().equals(expectedHeader.getName()))
                    .findFirst().orElse(null);

            Assert.assertNotNull(actualHeader);
            Assert.assertEquals(actualHeader.getValue().length, expectedHeader.getValue().length);
            Assert.assertEquals(actualHeader.getValue()[0], expectedHeader.getValue()[0]);
        }

        for (Param expectedParam : expectedRequest.getAdditionalParams()) {
            Param actualParam = actualAuthRequest.getAdditionalParams().stream()
                    .filter(p -> p.getName().equals(expectedParam.getName()))
                    .findFirst().orElse(null);

            Assert.assertNotNull(actualParam);
            Assert.assertEquals(actualParam.getValue().length, expectedParam.getValue().length);
            Assert.assertEquals(actualParam.getValue()[0], expectedParam.getValue()[0]);
        }
    }

    private void assertAllowedOperations(List<AllowedOperation> allowedOperationList) {

        Assert.assertEquals(allowedOperationList.size(), 1);
        Assert.assertEquals(Operation.REDIRECT, allowedOperationList.get(0).getOp());
    }

    private AuthenticationRequestEvent getExpectedEvent(AuthenticatedUser user, boolean isSubOrgFlow)
            throws Exception {

        AuthenticationRequestEvent.Builder eventBuilder = new AuthenticationRequestEvent.Builder();
        eventBuilder.tenant(new Tenant(String.valueOf(TENANT_ID_TEST), TENANT_DOMAIN_TEST));
        eventBuilder.application(new Application(TestFlowContextBuilder.SP_ID, TestFlowContextBuilder.SP_NAME));
        if (isSubOrgFlow) {
            eventBuilder.organization(new Organization.Builder()
                    .id(ORG_ID_TEST)
                    .name(ORG_NAME_TEST)
                    .orgHandle(ORG_HANDLE_TEST)
                    .depth(ORG_DEPTH_TEST)
                    .build());
        } else {
            eventBuilder.organization(new Organization.Builder()
                    .id(ROOT_ORG_ID_TEST)
                    .name(TENANT_DOMAIN_TEST)
                    .orgHandle(TENANT_DOMAIN_TEST)
                    .depth(0)
                    .build());
        }
        if (user != null) {
            eventBuilder.user(createAuthenticatingUser(user));
        }
        eventBuilder.request(new AuthenticationRequest.Builder()
                .additionalHeaders(this.headers.entrySet().stream()
                        .map(e -> new Header(e.getKey(), new String[]{e.getValue()}))
                        .collect(Collectors.toList()))
                .additionalParams(this.parameters.entrySet().stream()
                        .map(e -> new Param(e.getKey(), new String[]{e.getValue()}))
                        .collect(Collectors.toList()))
                .build());

        return eventBuilder.build();
    }

    private static AuthenticatingUser createAuthenticatingUser(AuthenticatedUser user) throws Exception {

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
