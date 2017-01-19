
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

/**
 * Interface for any class that implements a token service used in generating and validating CSRF tokens
 */
public interface CSRFTokenService {

    /**
     * Generates a site-wide URL-independent CSRF token with no token timeout.
     *
     * @return                              Generated CSRF token.
     * @throws CSRFTokenGenerationException if there is a problem generating the token.
     */
    public String generateToken() throws CSRFTokenGenerationException;

    /**
     * Generates a CSRF token based on the parameters specified by a token generation context.
     *
     * @param tokenGenerationContext        specifications according to which the token is to be generated.
     * @return                              Generated CSRF token.
     * @throws CSRFTokenGenerationException if there is a problem generating the token.
     */
    public String generateToken(CSRFTokenGenerationContext tokenGenerationContext)
            throws CSRFTokenGenerationException;

    /**
     * Retrieves the site wide CSRF token. Returns <code>null</code> if it does not exist.
     * <p>
     * Always returns <code>null</code> for HMAC based protection.
     *
     * @return  Site wide CSRF token, or <code>null</code> if one does not exist.
     */
    public String getToken();

    /**
     * Retrieves the CSRF token associated with the specified URL. Returns <code>null</code> if it does not exist.
     * <p>
     * Always returns <code>null</code> for HMAC based protection.
     *
     * @return  CSRF token associated with the given URL, or <code>null</code> if it does not exist.
     */
    public String getToken(String url);

    /**
     * Validates the specified CSRF token according to the specified token verification context.
     *
     * @param token                             token to be verified.
     * @param tokenVerificationContext          token verification context according to which the token is
     *                                          to be validated.
     * @return                                  <code>True</code> if token verification succeeds.
     * @throws CSRFTokenVerificationException   if there is a problem verifying the token.
     */
    public boolean verifyToken(String token, TokenVerificationContext tokenVerificationContext)
            throws CSRFTokenVerificationException;


    /**
     * Sets the client supplied user seed value used in creation of the token signature for HMAC based protection
     * from the <code>HttpServletRequest</code> object attribute specified in the configuration file.
     * <p>
     * Seed value ties a token to a user identity. The seed need not be cryptographically hashed and can be any value
     * unique to the authenticated user. The user seed should ideally be set within the application's authentication
     * filter or module. This will allow for the user seed to be set consistently on all authenticated requests. A default
     * seed value will be used if one is not provided.
     * <p>
     * Throws {@link CSRFTokenServiceException} if called from a token service that does not support user identities.
     *
     * @param userSeed                      user seed value supplied by the client in the <code>HttpServletRequest</code> object.
     * @throws CSRFTokenServiceException    when attempting to set user seed for a protection strategy that does not
     *                                      define user identities.
     */
    public void setUserSeed(String userSeed)
            throws CSRFTokenServiceException;

    /**
     * Sets the default site wide token timeout to be used for HMAC based protection. Any token older than the specified value
     * will be denied. Default timeout value is 30 minutes.
     * <p>
     * Throws {@link CSRFTokenServiceException} if called from a token service that does not support user identities.
     * @param defaultTokenTimeout           timeout value, in minutes, for site wide tokens.
     * @throws CSRFTokenServiceException    when attempting to set the default timeout for a protection strategy that
     *                                      does not use default token timeouts.
     */
    public void setDefaultTimeout(Long defaultTokenTimeout)
            throws CSRFTokenServiceException;


}