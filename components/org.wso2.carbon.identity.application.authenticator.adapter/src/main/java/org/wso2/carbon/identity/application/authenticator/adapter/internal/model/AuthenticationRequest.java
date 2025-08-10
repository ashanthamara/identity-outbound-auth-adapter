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

package org.wso2.carbon.identity.application.authenticator.adapter.internal.model;

import org.wso2.carbon.identity.action.execution.api.model.Header;
import org.wso2.carbon.identity.action.execution.api.model.Param;
import org.wso2.carbon.identity.action.execution.api.model.Request;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * This class holds the authentication request object which is communicated to the external authentication service.
 */
public class AuthenticationRequest extends Request {

    private AuthenticationRequest(Builder builder) {

        additionalHeaders.addAll(builder.additionalHeaders);
        additionalParams.addAll(builder.additionalParams);
    }

    /**
     * Builder for the AuthenticationRequest.
     */
    public static class Builder {

        private List<Header> additionalHeaders = new ArrayList<>();
        private List<Param> additionalParams = new ArrayList<>();

        public Builder additionalHeaders(List<Header> additionalHeaders) {

            this.additionalHeaders = additionalHeaders;
            return this;
        }

        public Builder additionalParams(List<Param> additionalParams) {

            this.additionalParams = additionalParams;
            return this;
        }

        public Builder fromHttpRequest(HttpServletRequest request) {

            if (request != null) {
                resolveHeaders(request);
                resolveParams(request);
            }
            return this;
        }

        public AuthenticationRequest build() {

            return new AuthenticationRequest(this);
        }

        private void resolveHeaders(HttpServletRequest request) {

            Enumeration headerNames = request.getHeaderNames();
            if (headerNames == null) {
                return;
            }

            while (headerNames.hasMoreElements()) {
                String headerName = (String) headerNames.nextElement();
                Enumeration headerValues = request.getHeaders(headerName);
                if (headerValues == null) {
                    continue;
                }

                List<String> values = new ArrayList<>();
                while (headerValues.hasMoreElements()) {
                    values.add((String) headerValues.nextElement());
                }
                this.additionalHeaders.add(new Header(headerName, values.toArray(new String[0])));
            }
        }

        private void resolveParams(HttpServletRequest request) {

            Enumeration paramNames = request.getParameterNames();
            if (paramNames == null) {
                return;
            }

            while (paramNames.hasMoreElements()) {
                String paramName = (String) paramNames.nextElement();
                String[] paramValues = request.getParameterValues(paramName);
                if (paramValues == null) {
                    continue;
                }
                this.additionalParams.add(new Param(paramName, paramValues));
            }
        }
    }
}
