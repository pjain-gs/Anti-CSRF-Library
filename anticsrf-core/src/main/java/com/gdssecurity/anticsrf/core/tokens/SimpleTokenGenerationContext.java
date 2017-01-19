
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

import com.gdssecurity.anticsrf.spi.rules.CSRFResourceProtectionRule;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenGenerationContext;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;

/**
 * Token generation context class implementing <code>CSRFTokenGenerationContext</code> containing specs
 * used in token generation
 */
public class SimpleTokenGenerationContext implements CSRFTokenGenerationContext {

    private final String resourceAddress;   //  URL for non site wide tokens.
    private final CSRFUserContext userContext;  //  User context with user identity information. Usually null in case of session based token storage service.
    private final CSRFResourceProtectionRule protectionRule;    //  Protection rule associated with the URL.

    /**
     * Initializes token context fields.
     *
     * @param resourceAddress   URL for non site wide tokens.
     * @param userContext       user context with user identity information. Usually <code>null</code> in case of session
     *                          based token storage service.
     * @param rule              protection rule associated with the URL.
     */
    public SimpleTokenGenerationContext(
            String resourceAddress,
            CSRFUserContext userContext,
            CSRFResourceProtectionRule rule) {

        this.resourceAddress = resourceAddress;
        this.userContext = userContext;
        this.protectionRule = rule;
    }

    /**
     * Gets the resource URL for which we are creating the token from the <code>HttpServletRequest</code>.
     *
     * @return Resource URL for with which to associate the token.
     */
    @Override
    public String getResourceURL() {
        return resourceAddress;
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
