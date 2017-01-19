
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

import org.apache.commons.lang3.StringUtils;

/**
 * Token object containing token specs stored in the <code>HttpSession</code> by the token storage service
 */
public class StoredToken {

    private final String tokenValue;    //  CSRF token.
    private final String url;           //  URL, if any, associated with token.
    private final Long tokenTimeout;    //  Timeout, if any, associated with token that determines duration of token validity.
    private final String userIdentifier;    //  User identity, if any, associated with token.
    private final boolean isOneTimeUseToken;    //  One time use token identifier.
    private final Long tokenTimestamp;  //  Token creation timestamp.

    /**
     * Constructor to initialize token specs.
     *
     * @param tokenValue                CSRF token.
     * @param url                       URL, if any, associated with token.
     * @param tokenTimeout              timeout value that determines duration of token validity.
     * @param userIdentifier            user identity, if any, associated with token.
     * @param isOneTimeUseToken         one time use token identifier.
     * @param tokenTimestamp            token creation timestamp.
     *
     * @throws IllegalArgumentException if token value is blank.
     */
    public StoredToken(
            String tokenValue,
            String url,
            Long tokenTimeout,
            String userIdentifier,
            boolean isOneTimeUseToken,
            Long tokenTimestamp) {

        if (StringUtils.isBlank(tokenValue)) {
            throw new IllegalArgumentException("Token value for session token cannot be blank");
        }
        this.tokenValue = tokenValue;
        this.url = url;
        this.tokenTimeout = tokenTimeout;
        this.userIdentifier = userIdentifier;
        this.isOneTimeUseToken = isOneTimeUseToken;
        this.tokenTimestamp = tokenTimestamp;
    }

    /**
     * Gets CSRF token value.
     *
     * @return  CSRF token value.
     */
    public String getTokenValue() {
        return tokenValue;
    }

    /**
     * Gets URL associated with token, or null for a site wide token.
     *
     * @return  URL associated with token, or null for a site wide token.
     */
    public String getResourceURL() {
        return url;
    }

    /**
     * Gets token timeout value, if one is specified, that determines duration token should be considered valids.
     *
     * @return  token timeout value, if specified.
     */
    public Long getTokenTimeout() {
        return tokenTimeout;
    }

    /**
     * Gets user identity associated with token, if it exists.
     *
     * @return  User identity associated with token, if it exists.
     */
    public String getUserIdentifier() {
        return userIdentifier;
    }

    /**
     * Returns <code>true</code> if token is a one time use token that should be removed from token context store
     * upon first retrieval for validation.
     *
     * @return   <code>True</code> if token is a one time use token.
     */
    public boolean isOneTimeUseToken() {
        return isOneTimeUseToken;
    }

    /**
     * Gets timestamp at token creation.
     *
     * @return  Timestamp at token creation.
     */
    public Long getTokenTimestamp() {
        return tokenTimestamp;
    }

}
