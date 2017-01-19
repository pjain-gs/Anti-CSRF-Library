
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

import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;

import javax.servlet.http.HttpServletRequest;

/**
 * Implements <code>CSRFRequestContext</code> to process J2EE <code>HttpServletRequest</code>
 * for tokens passed as request parameters
 */
public class J2EECSRFRequestContext implements CSRFRequestContext {

    private final String requestTokenParamName; //  Request parameter name used to pass the CSRF Token in requests.

    /**
     * Constructs request context with request parameter name used to pass CSRF tokens.
     *
     * @param requestTokenParamName request parameter name used to pass CSRF tokens.
     */
    public J2EECSRFRequestContext(String requestTokenParamName) {
        this.requestTokenParamName = requestTokenParamName;
    }

    /**
     * Gets URL from <code>HttpServletRequest</code>.
     *
     * @return  URL from client request.
     */
    @Override
    public String getRequestURL() {
        HttpServletRequest request = getRequest();
        return (request != null ? J2EEHelper.getRequestURL(request) : null);
    }

    /**
     * Gets the CSRF Token used in the J2EE requests from the request parameter, or <code>null</code> if there isn't
     * one.
     *
     * @return  CSRF token, or <code>null</code> if it does not exist.
     */
    @Override
    public String getRequestToken() {
        HttpServletRequest request = getRequest();
        return (request != null ? request.getParameter(requestTokenParamName) : null);
    }

    /**
     *  Gets the J2EE HttpServletRequest.
     */
    private static HttpServletRequest getRequest() {
        return J2EEServletContext.getRequest();
    }
}
