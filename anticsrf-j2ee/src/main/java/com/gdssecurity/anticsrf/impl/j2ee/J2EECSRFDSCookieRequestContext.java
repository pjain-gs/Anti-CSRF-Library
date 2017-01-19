/*
 * Copyright 2017 Gotham Digital Science LLC
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
//Portions copyright Goldman Sachs

package com.gdssecurity.anticsrf.impl.j2ee;

/**
 * Extends <code>J2EECSRFRequestContext</code> to process J2EE <code>HttpServletRequest</code>
 * for tokens passed in the HTTP headers
 *
 * @author Pallavi Jain
 */

import javax.servlet.http.HttpServletRequest;

/**
 * Implements <code>CSRFRequestContext</code> to process J2EE <code>HttpServletRequest</code>
 * for tokens passed as request headers
 */
public class J2EECSRFDSCookieRequestContext extends J2EECSRFRequestContext {

    private final String requestCSRFHeaderName; //  HTTP header name used to pass the CSRF Token in requests.

    /**
     * Constructs request context with HTTP header name and request parameter name used to pass CSRF tokens.
     *
     * @param requestTokenParamName request parameter name used to pass CSRF tokens.
     * @param requestCSRFHeaderName HTTP header name used to pass CSRF tokens.
     */
    public J2EECSRFDSCookieRequestContext(String requestTokenParamName, String requestCSRFHeaderName) {
        super(requestTokenParamName);
        this.requestCSRFHeaderName = requestCSRFHeaderName;
    }

    /**
     * Gets the CSRF Token used in the J2EE requests from the HTTP header, or <code>null</code> if there isn't
     * one.
     *
     * @return  CSRF token, or <code>null</code> if it does not exist.
     */
    @Override
    public String getRequestToken() {
        HttpServletRequest request = getRequest();
        return (request != null ? request.getHeader(requestCSRFHeaderName) : null);
    }

    /**
     *  Gets the J2EE HttpServletRequest.
     */
    private static HttpServletRequest getRequest() {
        return J2EEServletContext.getRequest();
    }
}
