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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionResponseContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationFailureResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationIncompleteResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.Error;
import org.wso2.carbon.identity.action.execution.api.model.ErrorStatus;
import org.wso2.carbon.identity.action.execution.api.model.FailedStatus;
import org.wso2.carbon.identity.action.execution.api.model.Failure;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Incomplete;
import org.wso2.carbon.identity.action.execution.api.model.IncompleteStatus;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.api.model.Success;
import org.wso2.carbon.identity.action.execution.api.model.SuccessStatus;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionResponseProcessor;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticatedUserData;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationActionExecutionResult;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationActionExecutionResult.Availability;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticationActionExecutionResult.Validity;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.util.AuthenticatedUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.util.DiagnosticLogger;
import org.wso2.carbon.identity.base.AuthenticatorPropertyConstants;

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

/**
 * This is responsible for processing authentication response from the external authentication service.
 */
public class AuthenticationResponseProcessor implements ActionExecutionResponseProcessor {

    private static final Log LOG = LogFactory.getLog(AuthenticationResponseProcessor.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.AUTHENTICATION;
    }

    @Override
    public ActionExecutionStatus<Success> processSuccessResponse(FlowContext flowContext,
            ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext)
            throws ActionExecutionResponseProcessorException {

        AuthenticationContext context = flowContext.getValue(
                AuthenticatorAdapterConstants.AUTH_CONTEXT, AuthenticationContext.class);
        AuthenticatorPropertyConstants.AuthenticationType authType = flowContext.getValue(
                AuthenticatorAdapterConstants.AUTH_TYPE, AuthenticatorPropertyConstants.AuthenticationType.class);

        if (AuthenticatorPropertyConstants.AuthenticationType.VERIFICATION.equals(authType)) {
            context.setSubject(context.getLastAuthenticatedUser());
            return new SuccessStatus.Builder().setResponseContext(flowContext.getContextData()).build();
        }

        /* The authentication type is set by the authenticator adapter, and for IDENTIFICATION authentication type,
         providing user data in the action authentication is mandatory.*/
        if (responseContext.getActionInvocationResponse().getData() == null) {
            String errorMessage = "The user field is missing in the authentication action response. This field " +
                    "is required for IDENTIFICATION authentication.";
            DiagnosticLogger.logSuccessResponseDataValidationError(new AuthenticationActionExecutionResult("",
                    Availability.UNAVAILABLE, Validity.INVALID, errorMessage));
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }
        AuthenticatedUserData authenticatedUserData =
                (AuthenticatedUserData) responseContext.getActionInvocationResponse().getData();
        AuthenticatedUser authenticatedUser = new AuthenticatedUserBuilder(authenticatedUserData, context)
                .buildAuthenticateduser();
        context.setSubject(authenticatedUser);

        return new SuccessStatus.Builder().setResponseContext(flowContext.getContextData()).build();
    }

    @Override
    public ActionExecutionStatus<Incomplete> processIncompleteResponse(FlowContext flowContext,
            ActionExecutionResponseContext<ActionInvocationIncompleteResponse> responseContext)
            throws ActionExecutionResponseProcessorException {

        HttpServletResponse response = flowContext.getValue(AuthenticatorAdapterConstants.AUTH_RESPONSE,
                HttpServletResponse.class);

        List<PerformableOperation> operationsToPerform = responseContext.getActionInvocationResponse().getOperations();
        validateOperationForIncompleteStatus(operationsToPerform);

        String url = operationsToPerform.get(0).getUrl();
        try {
            response.sendRedirect(operationsToPerform.get(0).getUrl());
            return new IncompleteStatus.Builder().responseContext(flowContext.getContextData()).build();
        } catch (IOException e) {
            throw new ActionExecutionResponseProcessorException(String.format(
                    "Error while redirecting to the URL: %s", url), e);
        }
    }

    private void validateOperationForIncompleteStatus(List<PerformableOperation> operationsToPerform)
            throws ActionExecutionResponseProcessorException {

        String errorMessage;
        String operationPath = "/operations/";

        if (operationsToPerform == null) {
            errorMessage = String.format("The list of performable operations is empty. For the INCOMPLETE action " +
                            "invocation status, there must be a REDIRECTION operation defined for the %s action type.",
                    getSupportedActionType());
            DiagnosticLogger.logIncompleteResponseExecutionResult(new AuthenticationActionExecutionResult(operationPath,
                    Availability.UNAVAILABLE, Validity.INVALID,
                    errorMessage));
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }

        if (operationsToPerform.size() != 1) {
            errorMessage = String.format("The list of performable operations must contain only one operation for " +
                    "the INCOMPLETE action invocation status for the %s action type.", getSupportedActionType());
            DiagnosticLogger.logIncompleteResponseExecutionResult(new AuthenticationActionExecutionResult(operationPath,
                    Availability.AVAILABLE, Validity.INVALID,
                    errorMessage));
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }

        if (!Operation.REDIRECT.equals(operationsToPerform.get(0).getOp())) {
            errorMessage = String.format("The operation defined for the INCOMPLETE action invocation status must be " +
                            "a REDIRECTION operation for the %s action type.", getSupportedActionType());
            DiagnosticLogger.logIncompleteResponseExecutionResult(new AuthenticationActionExecutionResult(operationPath,
                    Availability.UNAVAILABLE, Validity.INVALID,
                    errorMessage));
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }

        if (operationsToPerform.get(0).getUrl() == null) {
            errorMessage = String.format("The REDIRECTION operation defined for the INCOMPLETE action invocation " +
                    "status must have a valid URL for the %s action type.", getSupportedActionType());
            DiagnosticLogger.logIncompleteResponseExecutionResult(new AuthenticationActionExecutionResult(operationPath,
                    Availability.AVAILABLE, Validity.INVALID,
                    errorMessage));
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }
    }

    @Override
    public ActionExecutionStatus<Failure> processFailureResponse(FlowContext flowContext,
            ActionExecutionResponseContext<ActionInvocationFailureResponse> responseContext)
            throws ActionExecutionResponseProcessorException {

        AuthenticationContext context = flowContext.getValue(
                AuthenticatorAdapterConstants.AUTH_CONTEXT, AuthenticationContext.class);
        context.setProperty(FrameworkConstants.AUTH_ERROR_CODE,
                responseContext.getActionInvocationResponse().getFailureReason());
        context.setProperty(FrameworkConstants.AUTH_ERROR_MSG,
                responseContext.getActionInvocationResponse().getFailureDescription());

        return new FailedStatus(new Failure(
                responseContext.getActionInvocationResponse().getFailureReason(),
                responseContext.getActionInvocationResponse().getFailureDescription()));
    }

    @Override
    public ActionExecutionStatus<Error> processErrorResponse(FlowContext flowContext,
            ActionExecutionResponseContext<ActionInvocationErrorResponse> responseContext)
            throws ActionExecutionResponseProcessorException {

        /*  We do not set the error code and error message from the authentication action response to the authentication
         context, as these are internal details for the client side. */
        return new ErrorStatus(new Error(
                responseContext.getActionInvocationResponse().getErrorMessage(),
                responseContext.getActionInvocationResponse().getErrorDescription()));
    }
}

