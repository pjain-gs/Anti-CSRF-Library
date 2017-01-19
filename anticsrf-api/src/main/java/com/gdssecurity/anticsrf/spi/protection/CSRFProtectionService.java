
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

package com.gdssecurity.anticsrf.spi.protection;

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContextService;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesService;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenService;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContextService;

/**
 * Interface for any class that implements CSRF protection service to facilitate CSRF prevention
 */
public interface CSRFProtectionService {

    /**
     * Initializes the CSRF protection service with the token service, rules service, request
     * context service, user context service, configuration service, and logging service.
     * <p>
     * This method must be called in order to create the protection service object.
     *
     * @param tokenService              the interface to the token service managing token generation
     *                                  and verification processes.
     * @param rulesService              the interface to the rules service that processes the protection
     *                                  rules associated with the request URL.
     * @param requestContextService     the interface to the request context service that processes the
     *                                  <code>HttpServletRequest</code> object.
     * @param userContextService        the interface to the user context service that processes the user
     *                                  identity associated with a request.
     * @param configService             the interface to the configuration service managing
     *                                  settings for the behavior of the protection service.
     * @param loggingService            the interface to the logging facility for the protection
     *                                  service.
     */
    public void init(
            CSRFTokenService tokenService,
            CSRFRulesService rulesService,
            CSRFRequestContextService requestContextService,
            CSRFUserContextService userContextService,
            CSRFConfigService configService,
            CSRFLoggingService loggingService);

    /**
     * Generates a site wide token using the protection strategy specified in the configuration.
     *
     * @return                          Site wide token with no associated URL.
     * @throws CSRFProtectionException  if a failure occurred during the token generation.
     */
    public String generateToken() throws CSRFProtectionException;

    /**
     * Generates a token for the specified resource URL using the protection strategy specified
     * in the configuration, and the specified user context, if applicable.
     *
     * @return                          Token associated with the given URL and user context.
     * @throws CSRFProtectionException  if a failure occurred during the token generation.
     */
    public String generateResourceToken(String resourceURL, CSRFUserContext userContext)
            throws CSRFProtectionException;

    /**
     * Returns the site wide token, or <code>null</code> if one has not been generated.
     * <p>
     * This method will always return <code>null</code> for stateless protection strategies.
     *
     * @return                          Site wide token, or <code>null</code> if one has not been
     *                                  generated.
     */
    public String getToken();

    /**
     * Returns the token associated with the given URL, or <code>null</code> if one has not been
     * generated.
     * <p>
     * This method will always return <code>null</code> for stateless protection strategies.
     *
     * @return                          Token associated with the given URL, or <code>null</code>
     *                                  if one has not been generated.
     */
    public String getToken(String url);

    /**
     * Verifies the <code>HttpServletRequest</code> contains a valid request, and subsequently attempts token
     * validation using the protection strategy specified in the configuration.
     *
     * @return                          <code>True</code> if the request context contains a valid token, <code>false</code> otherwise.
     * @throws CSRFProtectionException  if a failure occurred during request context processing or token
     *                                  validation.
     */
    public boolean isVerifiedContextRequest() throws CSRFProtectionException;

    /**
     * Verifies the <code>HttpServletRequest</code> contains a request that can be validated, and subsequently
     * attempts to validate it using the protection strategy specified in the configuration.
     *
     * @return                          <code>True</code> if the request context contains a valid token, <code>false</code> otherwise.
     * @throws CSRFProtectionException  if a failure occurred during request context processing or token
     *                                  validation.
     */
    public boolean isVerifiedRequest(CSRFRequestContext requestContext, CSRFUserContext userContext)
            throws CSRFProtectionException;

    /**
     * Gets the interface to the configuration service with which the protection service was initialized.
     *
     * @return  {@link CSRFConfigService} interface managing settings for the behavior of the protection service.
     */
    public CSRFConfigService getConfigService();

    /**
     * Gets the interface to the logging service providing logging capabilities for the protection service.
     *
     * @return  {@link CSRFLoggingService} interface providing logging capabilities for the protection service.
     */
    public CSRFLoggingService getLoggingService();

    /**
     * Returns <code>true</code> if the configuration file designates protection rules for the specified URL.
     *
     * @param url   relative path URL to check for associated protection rules.
     * @return      <code>True</code> if there exists protection rules for the specified URL.
     */
    public boolean hasUrlSpecificConfig(String url);

    /**
     * Sets the client supplied user seed value used in creation of the token signature for HMAC based protection
     * from the <code>HttpServletRequest</code> object attribute specified in the configuration file.
     * <p>
     * Seed value ties a token to a user identity. The seed need not be cryptographically hashed and can be any value
     * unique to the authenticated user. The user seed should ideally be set within the application's authentication
     * filter or module. This will allow for the user seed to be set consistently on all authenticated requests. A default
     * seed value will be used if one is not provided.
     *
     * @param userSeed  user seed value supplied by the client in the <code>HttpServletRequest</code> object.
     */
    public void setUserSeed(String userSeed);

    /**
     * Sets the default site wide token timeout to be used for HMAC based protection. Any token older than the specified value
     * will be denied. Default timeout value is 30 minutes.
     *
     * @param defaultTokenTimeout   timeout value, in minutes, for site wide tokens.
     */
    public void setDefaultTimeout(Long defaultTokenTimeout);

}
