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
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.Error;
import org.wso2.carbon.identity.action.execution.api.model.ErrorStatus;
import org.wso2.carbon.identity.action.execution.api.model.FailedStatus;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.component.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.AuthenticatorPropertyConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.IS_IDF_INITIATED_FROM_AUTHENTICATOR;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.ENDPOINT_URL_SUFFIX;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.STATE_PARAM_SUFFIX;

/**
 * This class holds the external custom authentication.
 */
public abstract class AbstractAuthenticatorAdapter extends AbstractApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(AbstractAuthenticatorAdapter.class);
    protected String authenticatorName;
    protected String friendlyName;
    protected AuthenticatorPropertyConstants.AuthenticationType authenticationType = AuthenticatorPropertyConstants
            .AuthenticationType.IDENTIFICATION;

    private static final String errorCodeForClient = "authentication_processing_error";
    private static final String errorMessageForClient = "An error occurred while authenticating user with %s.";

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return true;
    }

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setI18nKey(getI18nKey());
        String idpName = context.getExternalIdP().getIdPName();
        authenticatorData.setIdp(idpName);

        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);
        authenticatorData.setAdditionalData(getAdditionalData(context));

        return Optional.of(authenticatorData);
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        try {
            if (context.isLogoutRequest()) {
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }

            /* When an identifier is initiated, the isIdfInitiatedFromAuthenticator property is set but never removed.
             During login, if this property exists, the current authenticator is set to null, overriding any selection.
             For custom authenticators, this causes unintended resets. To fix this, we remove the property in
             handleRequestFlow, ensuring the correct authenticator persists.
             */
            context.removeProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR);

            FlowContext flowContext = FlowContext.create();
            flowContext.add(AuthenticatorAdapterConstants.AUTH_REQUEST, request);
            flowContext.add(AuthenticatorAdapterConstants.AUTH_RESPONSE, response);
            flowContext.add(AuthenticatorAdapterConstants.AUTH_CONTEXT, context);
            flowContext.add(AuthenticatorAdapterConstants.AUTH_TYPE, getAuthenticationType());
            flowContext.add(AuthenticatorAdapterConstants.AUTHENTICATOR_NAME_PROP, getName());

            /* Execute the corresponding action from the authentication config and add the ActionExecutionStatus result
             to the context which will be used in processAuthenticationResponse method. */
            ActionExecutionStatus executionStatus = executeAction(context, flowContext, context.getTenantDomain());
            context.setProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME, executionStatus);

            if (executionStatus.getStatus() == ActionExecutionStatus.Status.INCOMPLETE) {
                context.setCurrentAuthenticator(getName());
                context.setRetrying(false);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }

            /* Invoke the process method in the AbstractApplicationAuthenticator class to continue processing the
              AuthenticationContext. */
            return super.process(request, response, context);
        } catch (ActionExecutionException e) {
            context.setProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME,
                    new ErrorStatus(
                            new Error("internal_error", String.format(e.getMessage()))));
            return super.process(request, response, context);
        } finally {
            context.removeProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME);
        }
    }

    private ActionExecutionStatus executeAction(AuthenticationContext context, FlowContext flowContext,
                                                String tenantDomain) throws ActionExecutionException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String actionId = authenticatorProperties.get(AuthenticatorAdapterConstants.ACTION_ID_CONFIG);

        ActionExecutionStatus executionStatus =
                AuthenticatorAdapterDataHolder.getInstance().getActionExecutorService()
                        .execute(ActionType.AUTHENTICATION, actionId, flowContext, tenantDomain);
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format(
                    "Invoked authentication action for Authentication flow ID: %s. Status: %s",
                    context.getContextIdentifier(),
                    Optional.ofNullable(executionStatus).isPresent() ? executionStatus.getStatus() : "NA"));
        }
        return executionStatus;
    }

    @Override
    public String getFriendlyName() {

        return friendlyName;
    }

    @Override
    public String getName() {

        return authenticatorName;
    }

    public AuthenticatorPropertyConstants.AuthenticationType getAuthenticationType() {

        return authenticationType;
    }

    @Override
    public String getClaimDialectURI() {

        return AuthenticatorAdapterConstants.WSO2_CLAIM_DIALECT;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        return new ArrayList<>();
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        throw new UnsupportedOperationException();
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        /* This method is invoked from the AbstractApplicationAuthenticator class to handle the authentication response.
         When the ActionExecutionStatus is SUCCESS, the authenticated user is built based on the action response in the
         processSuccessResponse method within the AuthenticationResponseProcessor class. In this method, if the
         ActionExecutionStatus is FAILED, an InvalidCredentialsException is thrown, and if the ActionExecutionStatus is
         ERROR, an AuthenticationFailedException is thrown. Based on the exception, the process method of the superclass
         updates the authentication context. */
        ActionExecutionStatus executionStatus = (ActionExecutionStatus)
                context.getProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME);
        if (executionStatus.getStatus() == ActionExecutionStatus.Status.FAILED) {
            throw new InvalidCredentialsException("An authentication failure response received from the " +
                    "authentication action." + ((FailedStatus) executionStatus).getResponse().getFailureDescription());
        } else if (executionStatus.getStatus() == ActionExecutionStatus.Status.ERROR) {
            setErrorContextForClient(context);
            throw new AuthenticationFailedException("An error occurred while authenticating user with authentication " +
                    "action." + ((ErrorStatus) executionStatus).getResponse().getErrorDescription());
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter("flowId");
    }

    @Override
    public String getI18nKey() {

        return AuthenticatorAdapterConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        /* The external server must handle the retry at authentication failure and after authentication with external
         service completed call back to the IS. */
        return false;
    }

    @Override
    public AuthenticatorPropertyConstants.DefinedByType getDefinedByType() {

        return AuthenticatorPropertyConstants.DefinedByType.USER;
    }

    private void setErrorContextForClient(AuthenticationContext context) {

        /* Get a generic error code and message to be sent to the client. An ErrorStatus is generated based on the
         action execution result, which will be evaluated and trigger an AuthenticationFailedException in the
         processAuthenticationResponse method.*/
        context.setProperty(FrameworkConstants.AUTH_ERROR_CODE, errorCodeForClient);
        context.setProperty(FrameworkConstants.AUTH_ERROR_MSG, String.format(errorMessageForClient, getFriendlyName()));
    }

    private AdditionalData getAdditionalData(AuthenticationContext context) {

        AdditionalData additionalData = new AdditionalData();

        Map<String, String> additionalAuthenticationParams = new HashMap<>();
        additionalAuthenticationParams.put(AuthenticatorAdapterConstants.PARAM_STATE,
                (String) context.getProperty(getName() + STATE_PARAM_SUFFIX));
        additionalAuthenticationParams.put(AuthenticatorAdapterConstants.PARAM_ENDPOINT_URL,
                (String) context.getProperty(getName() + ENDPOINT_URL_SUFFIX));
        additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);

        return additionalData;
    }
}
