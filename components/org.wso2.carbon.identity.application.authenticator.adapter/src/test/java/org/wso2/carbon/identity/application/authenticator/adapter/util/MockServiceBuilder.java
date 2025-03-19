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

package org.wso2.carbon.identity.application.authenticator.adapter.util;

import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;

import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.GROUP_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticationAdapterConstants.AuthenticatingUserConstants.USER_MULTI_VALUE_CLAIM_URI;

public class MockServiceBuilder {

    public static ClaimMetadataManagementService mockClaimMetadataManagementService(
            List<ClaimMapping> userClaimUriList, String tenantDomain) throws Exception {

        ClaimMetadataManagementService claimMetadataManagementService =
                mock(ClaimMetadataManagementService.class);

        for (ClaimMapping claimMapping : userClaimUriList) {
            LocalClaim localClaim;
            if (USER_MULTI_VALUE_CLAIM_URI.equals(claimMapping.getLocalClaim().getClaimUri()) ||
                    GROUP_CLAIM.equals(claimMapping.getLocalClaim().getClaimUri())) {
                localClaim = mockLocalMultiValuedClaim((claimMapping.getLocalClaim().getClaimUri()));
            } else {
                localClaim = mockLocalSingleValuedClaim((claimMapping.getLocalClaim().getClaimUri()));
            }
            when(claimMetadataManagementService.getLocalClaim(
                    claimMapping.getLocalClaim().getClaimUri(), tenantDomain)
            ).thenReturn(Optional.of(localClaim));
        }
        return claimMetadataManagementService;
    }

    private static LocalClaim mockLocalMultiValuedClaim(String claimUri) {

        LocalClaim localClaim = mock(LocalClaim.class);
        when(localClaim.getClaimURI()).thenReturn(claimUri);
        when(localClaim.getClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY)).thenReturn("true");

        return localClaim;
    }

    private static LocalClaim mockLocalSingleValuedClaim(String claimUri) {

        LocalClaim localClaim = mock(LocalClaim.class);
        when(localClaim.getClaimURI()).thenReturn(claimUri);
        when(localClaim.getClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY)).thenReturn("false");

        return localClaim;
    }
}
