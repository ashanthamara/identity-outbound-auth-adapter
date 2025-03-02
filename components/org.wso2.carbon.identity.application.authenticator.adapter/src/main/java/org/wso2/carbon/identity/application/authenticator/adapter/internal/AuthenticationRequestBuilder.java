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
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationRequestEvent;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationRequestEvent.AuthenticatedStep;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This is a builder class which is responsible for building authentication request payload which will be sent to the
 * external authentication service.
 */
public class AuthenticationRequestBuilder implements ActionExecutionRequestBuilder {

    private static final Log LOG = LogFactory.getLog(AuthenticationRequestBuilder.class);

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.AUTHENTICATION;
    }

    @Override
    public ActionExecutionRequest buildActionExecutionRequest(FlowContext flowContext,
                                                              ActionExecutionRequestContext actionExecutionContext)
            throws ActionExecutionRequestBuilderException {

        AuthenticationContext context = flowContext.getValue(
                AuthenticatorAdapterConstants.AUTH_CONTEXT, AuthenticationContext.class);

        ActionExecutionRequest.Builder actionRequestBuilder = new ActionExecutionRequest.Builder();
        actionRequestBuilder.flowId(context.getContextIdentifier());
        actionRequestBuilder.actionType(getSupportedActionType());
        actionRequestBuilder.event(getEvent(context));
        actionRequestBuilder.allowedOperations(getAllowedOperations());

        return actionRequestBuilder.build();
    }

    private Event getEvent(AuthenticationContext context) throws ActionExecutionRequestBuilderException {

        AuthenticatedUser currentAuthenticatedUser = context.getLastAuthenticatedUser();
        String tenantDomain = context.getTenantDomain();

        AuthenticationRequestEvent.Builder eventBuilder = new AuthenticationRequestEvent.Builder();
        eventBuilder.tenant(new Tenant(String.valueOf(IdentityTenantUtil.getTenantId(tenantDomain)), tenantDomain));
        if (currentAuthenticatedUser != null) {
            eventBuilder.user(getUserForEventBuilder(currentAuthenticatedUser));
            eventBuilder.organization(getOrganizationForEventBuilder(currentAuthenticatedUser));
            eventBuilder.userStore(new UserStore(currentAuthenticatedUser.getUserStoreDomain()));
        }
        eventBuilder.application(new Application(context.getServiceProviderResourceId(),
                context.getServiceProviderName()));
        eventBuilder.currentStepIndex(context.getCurrentStep());
        eventBuilder.authenticatedSteps(getAuthenticatedStepsForEventBuilder(context));
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

    private Organization getOrganizationForEventBuilder(AuthenticatedUser authenticatedUser) {

        String organizationId = authenticatedUser.getUserResidentOrganization();
        try {
            if (organizationId != null && !organizationId.isEmpty()) {
                String organizationName = AuthenticatorAdapterDataHolder.getInstance().getOrganizationManager()
                        .getOrganizationNameById(authenticatedUser.getUserResidentOrganization());
                return new Organization(authenticatedUser.getUserResidentOrganization(), organizationName);
            }
        } catch (OrganizationManagementException e) {
            LOG.debug("Error occurred while retrieving organization name of the authorized user: " + organizationId, e);
            return null;
        }

        LOG.debug("The organization id is not set for the authorized user with username: "
                + authenticatedUser.getUserName());
        return null;
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
}
