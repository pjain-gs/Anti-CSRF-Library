
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

package com.gdssecurity.anticsrf.core.protection;

import com.gdssecurity.anticsrf.core.tokens.SimpleTokenGenerationContext;
import com.gdssecurity.anticsrf.core.tokens.SimpleTokenVerificationContext;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionException;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionService;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContextService;
import com.gdssecurity.anticsrf.spi.rules.CSRFResourceProtectionRule;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesService;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenGenerationContext;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenGenerationException;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenService;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenVerificationException;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContextService;
import org.apache.commons.lang3.StringUtils;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Default protection service class implementing <code>CSRFProtectionService</code> and contains all underlying
 * services to facilitate CSRF prevention
 */
public class DefaultCSRFProtectionService implements CSRFProtectionService {

    private CSRFTokenService tokenService;
    private CSRFRulesService rulesService;
    private CSRFRequestContextService requestContextService;
    private CSRFUserContextService userContextService;
    private CSRFConfigService configService;
    private CSRFLoggingService loggingService;

    // Ensure initialization only occurs once
    private boolean isInitialized = false;

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
    @Override
    public void init(
            CSRFTokenService tokenService,
            CSRFRulesService rulesService,
            CSRFRequestContextService requestContextService,
            CSRFUserContextService userContextService,
            CSRFConfigService configService,
            CSRFLoggingService loggingService) {

        // Synchronize access so we only ever create one instance
        synchronized (this) {
            if (isInitialized) {
                throw new CSRFProtectionException(
                        "Attempt to initialize already initialized" +
                                " protection service instance");
            }
            this.tokenService = tokenService;
            this.rulesService = rulesService;
            this.requestContextService = requestContextService;
            this.userContextService = userContextService;
            this.configService = configService;
            this.loggingService = loggingService;

            this.isInitialized = true;
        }
    }

    /**
     * Verifies the <code>HttpServletRequest</code> contains a valid request, and subsequently attempts token
     * validation using the protection strategy specified in the configuration.
     *
     * @return                          <code>True</code> if the request context contains a valid token, <code>false</code> otherwise.
     * @throws CSRFProtectionException  if a failure occurred during request context processing or token
     *                                  validation.
     */
    @Override
    public boolean isVerifiedContextRequest() throws CSRFProtectionException {
        // User context can be null in case of session based protection, but request context can never
        // be null regardless of protection mode.
        if (requestContextService == null) {
            throw new CSRFProtectionException(
                    "No request context service available " +
                            "for processing requested validation");
        }
        CSRFRequestContext requestContext = requestContextService.getCSRFRequestContext();

        if (requestContext == null) {
            throw new CSRFProtectionException(
                    "Request context service did not return a " +
                            "context for processing requested validation");
        }
        CSRFUserContext userContext = (userContextService != null ? userContextService.getUserContext() : null);
        return isVerifiedRequest(requestContext, userContext);
    }

    /**
     * Verifies the <code>HttpServletRequest</code> contains a request that can be validated, and subsequently
     * attempts to validate it using the protection strategy specified in the configuration.
     *
     * @return                          <code>True</code> if the request context contains a valid token, <code>false</code> otherwise.
     * @throws CSRFProtectionException  if a failure occurred during request context processing or token
     *                                  validation.
     */
    @Override
    public boolean isVerifiedRequest(CSRFRequestContext requestContext, CSRFUserContext userContext)
            throws CSRFProtectionException {
        // Request context can never be null regardless of protection mode.
        if (requestContext == null) {
            throw new CSRFProtectionException("No request context supplied for request validation");
        }
        // Check for protection rules for this request.
        CSRFResourceProtectionRule resourceProtectionRule = rulesService.getProtectionRuleForRequest(requestContext);

        // Create a context object containing URL, user seed, timeout, and protection rules, according to which the token will be validated.
        SimpleTokenVerificationContext tokenVerificationContext =
                new SimpleTokenVerificationContext(requestContext, userContext, resourceProtectionRule);

        String requestURL = requestContext.getRequestURL();
        String requestToken = requestContext.getRequestToken();
        // User identifier can be null in both session-based and HMAC protection. However, in the latter case,
        // the default user seed will ultimately be used in validation.
        String userIdentifier = (userContext != null ? userContext.getUserIdentifier() : null);

        try {
            // Validate token according to protection mode.
            return tokenService.verifyToken(requestToken, tokenVerificationContext);
        } catch (CSRFTokenVerificationException ex) {
            throw new CSRFProtectionException(
                    "Failed to validate request." +
                            " request URL = " + requestURL + "," +
                            " user identifier = " + userIdentifier + "," +
                            " request token = " + requestToken,
                    ex);
        }
    }

    /**
     * Generates a site wide token using the protection strategy specified in the configuration.
     *
     * @return                          Site wide token with no associated URL.
     * @throws CSRFProtectionException  if a failure occurred during the token generation.
     */
    @Override
    public String generateToken() throws CSRFProtectionException {
        try {
            // Generate token according to protection mode.
            return tokenService.generateToken();
        } catch (CSRFTokenGenerationException ex) {
            throw new CSRFProtectionException("Failed to generate token", ex);
        }
    }

    /**
     * Generates a token for the specified resource URL using the protection strategy specified
     * in the configuration, and the specified user context, if applicable.
     *
     * @return                          Token associated with the given URL and user context.
     * @throws CSRFProtectionException  if a failure occurred during the token generation.
     */
    @Override
    public String generateResourceToken(String resourceURL, CSRFUserContext userContext)
            throws CSRFProtectionException {

        String urlToken = getToken(resourceURL);    // Return any pre-existing token for this URL.
        if (StringUtils.isBlank(urlToken)) {
            // Certain data will be stored with the token, e.g. timeout, protection rules,
            // to aid in validation.
            CSRFResourceProtectionRule rule = rulesService.getProtectionRuleForResource(resourceURL);

            CSRFTokenGenerationContext tokenGenerationContext =
                    new SimpleTokenGenerationContext(resourceURL, userContext, rule);
            // Generate token according to protection mode.
            try {
                return tokenService.generateToken(tokenGenerationContext);
            } catch (CSRFTokenGenerationException ex) {
                throw new CSRFProtectionException("Failed to generate token", ex);
            }
        }
        return urlToken;
    }

    /**
     * Gets the configuration service with which the protection service was initialized.
     *
     * @return  {@link CSRFConfigService} managing settings for the behavior of the protection service.
     */
    @Override
    public CSRFConfigService getConfigService() {
        return configService;
    }

    /**
     * Gets the logging service providing logging capabilities for the protection service.
     *
     * @return  {@link CSRFLoggingService} providing logging capabilities for the protection service.
     */
    @Override
    public CSRFLoggingService getLoggingService() {
        return loggingService;
    }

    /**
     * Returns the site wide token, or <code>null</code> if one has not been generated.
     * <p>
     * This method will always return <code>null</code> for stateless protection strategies.
     *
     * @return                          Site wide token, or <code>null</code> if one has not been
     *                                  generated.
     */
    @Override
    public String getToken() {
        return tokenService.getToken();
    }

    /**
     * Returns the token associated with the given URL, or <code>null</code> if one has not been
     * generated.
     * <p>
     * This method will always return <code>null</code> for stateless protection strategies.
     *
     * @return                          Token associated with the given URL, or <code>null</code>
     *                                  if one has not been generated.
     */
    @Override
    public String getToken(String url) {
        // If specified URL does not have a specific configuration, return the site wide token.
        return hasUrlSpecificConfig(url) ? tokenService.getToken(url) : tokenService.getToken(null);
    }

    /**
     * Returns <code>true</code> if the configuration file designates protection rules for the specified URL.
     *
     * @param url   relative path URL to check for associated protection rules.
     * @return      <code>True</code> if there exists protection rules for the specified URL.
     */
    @Override
    public boolean hasUrlSpecificConfig(String url) {
        if (url == null) {
            return false;
        }
        // Check the config service properties loaded from the config file for a list of all
        // URL specific entries and match against the specified URL.
        List<Map.Entry<String, Long>> specificUrls = configService.getUrlSpecificRuleEntries();
        Iterator<Map.Entry<String, Long>> it = specificUrls.iterator();
        while (it.hasNext())
            if (StringUtils.equals(it.next().getKey(), url))
                return true;
        return false;
    }

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
    @Override
    public void setUserSeed(String userSeed) {
        tokenService.setUserSeed(userSeed);
    }

    /**
     * Sets the default site wide token timeout to be used for HMAC based protection. Any token older than the specified value
     * will be denied. Default timeout value is 30 minutes.
     *
     * @param defaultTokenTimeout   timeout value, in minutes, for site wide tokens.
     */
    @Override
    public void setDefaultTimeout(Long defaultTokenTimeout) {
        if (defaultTokenTimeout > 0)
                tokenService.setDefaultTimeout(defaultTokenTimeout);
    }

}
