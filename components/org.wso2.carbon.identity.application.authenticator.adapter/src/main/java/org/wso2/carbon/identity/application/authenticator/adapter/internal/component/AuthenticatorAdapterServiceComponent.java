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

package org.wso2.carbon.identity.application.authenticator.adapter.internal.component;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionRequestBuilder;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionResponseProcessor;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutorService;
import org.wso2.carbon.identity.action.execution.api.service.ActionInvocationResponseClassProvider;
import org.wso2.carbon.identity.application.authentication.framework.UserDefinedAuthenticatorService;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticationInvocationResponseClassProvider;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticationRequestBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticationResponseProcessor;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.UserDefinedAuthenticatorServiceImpl;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handles registration and unregistration of UserDefinedAuthenticatorService.
 */
@Component(
        name = "identity.application.authenticator.adapter",
        immediate = true
)
public class AuthenticatorAdapterServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticatorAdapterServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            ctxt.getBundleContext().registerService(UserDefinedAuthenticatorService.class,
                    new UserDefinedAuthenticatorServiceImpl(), null);
            ctxt.getBundleContext().registerService(ActionExecutionRequestBuilder.class,
                    new AuthenticationRequestBuilder(), null);
            ctxt.getBundleContext().registerService(ActionExecutionResponseProcessor.class,
                    new AuthenticationResponseProcessor(), null);
            ctxt.getBundleContext().registerService(ActionInvocationResponseClassProvider.class,
                    new AuthenticationInvocationResponseClassProvider(), null);

            if (log.isDebugEnabled()) {
                log.debug("The Authentication adapter bundle is activated.");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating Authentication adapter.", e);
        }
    }

    @Reference(
            name = "action.execution.service",
            service = ActionExecutorService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterActionExecutorService"
    )
    protected void registerActionExecutionService(ActionExecutorService actionExecutorService) {

        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(actionExecutorService);
        log.debug("Registering the ActionExecutorService in AuthenticatorAdapterServiceComponent.");
    }

    protected void unregisterActionExecutorService(ActionExecutorService actionExecutorService) {

        log.debug("Unregistering the ActionExecutorService in AuthenticatorAdapterServiceComponent.");
        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(null);
    }

    @Reference(
            name = "organization.service",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        log.debug("Registering the organization management service in AuthenticatorAdapterServiceComponent.");
        AuthenticatorAdapterDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        log.debug("Unregistering organization management service in AuthenticatorAdapterServiceComponent.");
        AuthenticatorAdapterDataHolder.getInstance().setOrganizationManager(null);
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        log.debug("Registering the Realm Service in AuthenticatorAdapterServiceComponent.");
        AuthenticatorAdapterDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("Unregistering the Realm Service in AuthenticatorAdapterServiceComponent.");
        AuthenticatorAdapterDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "claim.metadata.management.service",
            service = org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimMetadataManagementService")
    protected void setClaimMetadataManagementService(ClaimMetadataManagementService claimManagementService) {

        AuthenticatorAdapterDataHolder.getInstance().setClaimManagementService(claimManagementService);
        log.debug("ClaimMetadataManagementService set in AuthenticatorAdapterServiceComponent.");
    }

    protected void unsetClaimMetadataManagementService(ClaimMetadataManagementService claimManagementService) {

        AuthenticatorAdapterDataHolder.getInstance().setClaimManagementService(null);
        log.debug("ClaimMetadataManagementService unset in AuthenticatorAdapterServiceComponent.");
    }
}
