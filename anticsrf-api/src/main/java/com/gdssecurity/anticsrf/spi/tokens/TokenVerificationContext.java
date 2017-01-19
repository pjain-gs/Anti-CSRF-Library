
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

package com.gdssecurity.anticsrf.spi.tokens;

import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.rules.CSRFResourceProtectionRule;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;

/**
 * Interface for the token verification context used during validation of a CSRF token
 */
public interface TokenVerificationContext {

    /**
     * Gets the request context associated with the <code>HttpServletRequest</code>.
     *
     * @return {@link CSRFRequestContext} to facilitate parsing the client request.
     */
    public CSRFRequestContext getRequestContext();

    /**
     * Gets the user context associated with the <code>HttpServletRequest</code>.
     *
     * @return {@link CSRFUserContext} to facilitate parsing the client request for user identity.
     */
    public CSRFUserContext getUserContext();

    /**
     * Gets the protection rule associated with the current <code>HttpServletRequest</code>.
     *
     * @return {@link CSRFResourceProtectionRule} associated with URL parsed from the client request.
     */
    public CSRFResourceProtectionRule getResourceProtectionRule();

}
