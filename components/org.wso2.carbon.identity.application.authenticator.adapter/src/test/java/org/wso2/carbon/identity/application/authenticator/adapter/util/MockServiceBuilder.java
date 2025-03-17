package org.wso2.carbon.identity.application.authenticator.adapter.util;

import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;

import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.GROUP_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants.MULTI_VALUED_PROPERTY;
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
        when(localClaim.getClaimProperty(MULTI_VALUED_PROPERTY)).thenReturn("true");

        return localClaim;
    }

    private static LocalClaim mockLocalSingleValuedClaim(String claimUri) {

        LocalClaim localClaim = mock(LocalClaim.class);
        when(localClaim.getClaimURI()).thenReturn(claimUri);
        when(localClaim.getClaimProperty(MULTI_VALUED_PROPERTY)).thenReturn("false");

        return localClaim;
    }
}
