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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequestContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.api.model.Application;
import org.wso2.carbon.identity.action.execution.api.model.Event;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.Organization;
import org.wso2.carbon.identity.action.execution.api.model.Request;
import org.wso2.carbon.identity.action.execution.api.model.Tenant;
import org.wso2.carbon.identity.action.execution.api.model.User;
import org.wso2.carbon.identity.action.execution.api.model.UserStore;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionRequestBuilder;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.component.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticatingUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationRequestEvent;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationRequestEvent.AuthenticatedStep;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * This is a builder class which is responsible for building authentication request payload which will be sent to the
 * external authentication service.
 */
public class AuthenticationRequestBuilder implements ActionExecutionRequestBuilder {

    private static final Log LOG = LogFactory.getLog(AuthenticationRequestBuilder.class);

    private static final OrganizationManager organizationManager = AuthenticatorAdapterDataHolder.getInstance()
            .getOrganizationManager();

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.AUTHENTICATION;
    }

    @Override
    public ActionExecutionRequest buildActionExecutionRequest(FlowContext flowContext,
                                                              ActionExecutionRequestContext actionExecutionContext)
            throws ActionExecutionRequestBuilderException {

        HttpServletRequest request = flowContext.getValue(
                AuthenticatorAdapterConstants.AUTH_REQUEST, HttpServletRequest.class);
        AuthenticationContext context = flowContext.getValue(
                AuthenticatorAdapterConstants.AUTH_CONTEXT, AuthenticationContext.class);

        ActionExecutionRequest.Builder actionRequestBuilder = new ActionExecutionRequest.Builder();
        actionRequestBuilder.flowId(context.getContextIdentifier());
        actionRequestBuilder.actionType(getSupportedActionType());
        actionRequestBuilder.event(getEvent(request, context));
        actionRequestBuilder.allowedOperations(getAllowedOperations());

        return actionRequestBuilder.build();
    }

    private Event getEvent(HttpServletRequest request, AuthenticationContext context)
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser currentAuthenticatedUser = context.getLastAuthenticatedUser();

        AuthenticationRequestEvent.Builder eventBuilder = new AuthenticationRequestEvent.Builder();
        setTenantAndOrganizationToEventBuilder(eventBuilder, context);
        if (currentAuthenticatedUser != null) {
            eventBuilder.user(getUserForEventBuilder(currentAuthenticatedUser));
            eventBuilder.userStore(new UserStore(currentAuthenticatedUser.getUserStoreDomain()));
        }
        eventBuilder.application(new Application(context.getServiceProviderResourceId(),
                context.getServiceProviderName()));
        eventBuilder.currentStepIndex(context.getCurrentStep());
        eventBuilder.authenticatedSteps(getAuthenticatedStepsForEventBuilder(context));
        eventBuilder.request(getRequest(request, context));
        return eventBuilder.build();
    }

    private User getUserForEventBuilder(AuthenticatedUser authenticatedUser)
            throws ActionExecutionRequestBuilderException {

        try {
            return new AuthenticatingUser(authenticatedUser.getUserId(), authenticatedUser);
        } catch (UserIdNotFoundException e) {
            throw new ActionExecutionRequestBuilderException("User ID not found for current authenticated user.", e);
        }
    }

    private void setTenantAndOrganizationToEventBuilder(AuthenticationRequestEvent.Builder eventBuilder,
                                                        AuthenticationContext context)
            throws ActionExecutionRequestBuilderException {

        String tenantDomain = context.getTenantDomain();
        Tenant tenant = getTenantFromIdentityContext();
        Organization organization = getOrganizationFromIdentityContext();

        if (tenant != null && organization != null && StringUtils.equals(tenantDomain, organization.getOrgHandle())) {
            eventBuilder.tenant(tenant);
            eventBuilder.organization(organization);
            return;
        }

        // Fallback logic to resolve tenant and organization information when not available in the identity context.
        try {
            String orgId = organizationManager.resolveOrganizationId(tenantDomain);
            MinimalOrganization minimalOrg = organizationManager.getMinimalOrganization(orgId, tenantDomain);
            if (minimalOrg == null) {
                throw new ActionExecutionRequestBuilderException(
                        "Unable to find organization information for the tenant: " + tenantDomain);
            }

            eventBuilder.organization(new Organization.Builder()
                    .id(minimalOrg.getId())
                    .name(minimalOrg.getName())
                    .orgHandle(minimalOrg.getOrganizationHandle())
                    .depth(minimalOrg.getDepth())
                    .build());

            if (minimalOrg.getDepth() > 0) {
                // If the depth is greater than 0, it is a sub-organization. Resolving the root tenant domain.
                tenantDomain = OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(tenantDomain);
            }
            eventBuilder.tenant(new Tenant(String.valueOf(IdentityTenantUtil.getTenantId(tenantDomain)), tenantDomain));
        } catch (OrganizationManagementException e) {
            throw new ActionExecutionRequestBuilderException(String.format("Error occurred while retrieving " +
                    "organization details for the tenant %s in authentication context.", tenantDomain), e);
        }
    }

    private Tenant getTenantFromIdentityContext() {

        RootOrganization rootOrganization = IdentityContext.getThreadLocalIdentityContext().getRootOrganization();
        if (rootOrganization == null) {
            return null;
        }

        return new Tenant(String.valueOf(rootOrganization.getAssociatedTenantId()),
                rootOrganization.getAssociatedTenantDomain());
    }

    private Organization getOrganizationFromIdentityContext() {

        org.wso2.carbon.identity.core.context.model.Organization organization =
                IdentityContext.getThreadLocalIdentityContext().getOrganization();
        if (organization == null) {
            return null;
        }

        return new Organization.Builder()
                .id(organization.getId())
                .name(organization.getName())
                .orgHandle(organization.getOrganizationHandle())
                .depth(organization.getDepth())
                .build();
    }

    private AuthenticatedStep[] getAuthenticatedStepsForEventBuilder(AuthenticationContext context) {

        ArrayList<AuthenticatedStep> authenticatedSteps = new ArrayList<>();
        int stepIndex = 1;
        for (AuthHistory step: context.getAuthenticationStepHistory()) {
            authenticatedSteps.add(new AuthenticatedStep(stepIndex, step));
            stepIndex += 1;
        }

        return authenticatedSteps.toArray(new AuthenticatedStep[0]);
    }

    private List<AllowedOperation> getAllowedOperations() {

        AllowedOperation operation = new AllowedOperation();
        operation.setOp(Operation.REDIRECT);
        return Collections.singletonList(operation);
    }

    private Request getRequest(HttpServletRequest httpServletRequest, AuthenticationContext context) {

        if (httpServletRequest == null) {
            LOG.debug("HttpServletRequest is null. Additional headers and parameters will not be added to the " +
                    "authentication request.");
            return null;
        }

        return new AuthenticationRequest.Builder()
                .fromHttpRequest(httpServletRequest)
                .fromInitialAuthorizeRequest(context.getQueryParams())
                .build();
    }
}
