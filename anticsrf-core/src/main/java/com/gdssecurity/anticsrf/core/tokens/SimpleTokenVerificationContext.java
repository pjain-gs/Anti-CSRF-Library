
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

package com.gdssecurity.anticsrf.core.tokens;

import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.rules.CSRFResourceProtectionRule;
import com.gdssecurity.anticsrf.spi.tokens.TokenVerificationContext;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;

/**
 * Token verification context class implementing <code>CSRFTokenVerificationContext</code> containing specs
 * used in token validation
 */
public class SimpleTokenVerificationContext implements TokenVerificationContext {

    private final CSRFRequestContext requestContext;    //  Request context used in parsing client request.
    private final CSRFUserContext userContext;   //  User context with user identity information. Usually null in case of session based token storage service.
    private final CSRFResourceProtectionRule protectionRule;    //  Protection rule associated with the URL.

    /**
     * Initializes token context fields.
     *
     * @param requestContext    request context to parse for URL and check for associated protection rules.
     * @param userContext       user context with user identity information. Usually <code>null</code> in case of session
     *                          based token storage service.
     * @param rule              protection rule associated with the URL.
     */
    public SimpleTokenVerificationContext(
            CSRFRequestContext requestContext,
            CSRFUserContext userContext,
            CSRFResourceProtectionRule rule) {

        this.requestContext = requestContext;
        this.userContext = userContext;
        this.protectionRule = rule;
    }

    /**
     * Gets the request context associated with the <code>HttpServletRequest</code>.
     *
     * @return {@link CSRFRequestContext} to facilitate parsing the client request.
     */
    @Override
    public CSRFRequestContext getRequestContext() {
        return requestContext;
    }

    /**
     * Gets the user context associated with the <code>HttpServletRequest</code>.
     *
     * @return {@link CSRFUserContext} to facilitate parsing the client request for user identity.
     */
    @Override
    public CSRFUserContext getUserContext() {
        return userContext;
    }

    /**
     * Gets the protection rule associated with the current <code>HttpServletRequest</code>.
     *
     * @return {@link CSRFResourceProtectionRule} associated with URL parsed from the client request.
     */
    @Override
    public CSRFResourceProtectionRule getResourceProtectionRule() {
        return protectionRule;
    }

}
