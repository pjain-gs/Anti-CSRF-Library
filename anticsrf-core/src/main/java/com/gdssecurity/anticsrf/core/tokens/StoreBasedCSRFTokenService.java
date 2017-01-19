
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

import com.gdssecurity.anticsrf.core.api.store.CSRFTokenContextStore;
import com.gdssecurity.anticsrf.core.api.store.CSRFTokenStorageService;
import com.gdssecurity.anticsrf.core.util.SecureCompare;
import com.gdssecurity.anticsrf.spi.logging.CSRFLogger;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.rules.CSRFResourceProtectionRule;
import com.gdssecurity.anticsrf.spi.tokens.*;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;
import org.apache.commons.lang3.StringUtils;

import javax.xml.bind.DatatypeConverter;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;


/**
 * Storage based token service class implementing <code>CSRFTokenService</code>
 *
 * @author ononic
 */
final class StoreBasedCSRFTokenService implements CSRFTokenService {

    private final CSRFLogger logger;
    private final CSRFTokenStorageService tokenStorageService;

    /**
     * Constructor to initialize storage based token service.
     *
     * @param tokenStorageService   token storage service object used to manage tokens.
     * @param loggingService        logging facility used by the store based service.
     */
    StoreBasedCSRFTokenService(CSRFTokenStorageService tokenStorageService, CSRFLoggingService loggingService) {
        this.tokenStorageService = tokenStorageService;
        this.logger = loggingService.getLogger(StoreBasedCSRFTokenService.class);
    }

    /**
     * Generates a site-wide URL-independent CSRF token with no token timeout.
     *
     * @return                              Generated CSRF token.
     * @throws CSRFTokenGenerationException if there is a problem generating the token.
     */
    @Override
    public String generateToken() throws CSRFTokenGenerationException {
        return generateToken(null);
    }


    /**
     * Generates a CSRF token and stores it according to the parameters specified by the token generation context.
     * If a token context is supplied for a specific URL, a unique token will be generated for that URL and
     * stored separately using the token storage service.
     *
     * @param tokenContext                  specifications according to which the token is to be stored.
     * @return                              Generated CSRF token.
     * @throws CSRFTokenGenerationException if there is a problem generating the token.
     */
    @Override
    public String generateToken(CSRFTokenGenerationContext tokenContext) throws CSRFTokenGenerationException {
        CSRFResourceProtectionRule protectionRule = null;
        CSRFUserContext userContext = null;
        String url = tokenContext != null ? tokenContext.getResourceURL() : null;
        Long tokenTimeout = null;
        String userSeed = null;

        if (tokenContext != null) { // Token context will be null for a site wide token.
            url = tokenContext.getResourceURL();
            //  Check if token already exists for this URL and return if it does.
            if (!StringUtils.isBlank(url)) {
                String storedTokenValue = getToken(url);
                if (!StringUtils.isBlank(storedTokenValue))
                    return storedTokenValue;
            }

            protectionRule = tokenContext.getResourceProtectionRule();
            userContext = tokenContext.getUserContext();
            if (protectionRule != null)
                tokenTimeout = protectionRule.getTokenTimeout();
            if (userContext != null)
                userSeed = userContext.getUserIdentifier();
        }
        //  If a protection rule is specified for this URL and contains a token timeout of zero,
        //  this token will no longer be valid after one use.
        boolean isOneTimeUseToken = (tokenTimeout != null && tokenTimeout == 0);

        SecureRandom secureRandom;

        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException ex) {
            throw new CSRFTokenGenerationException(
                    "Failed to generate CSRFToken using Sun SecureRandom", ex);
        } catch (NoSuchProviderException ex) {

            //   Let's try and get the preferred one if SUN doesn't exist.

            try {
                secureRandom = SecureRandom.getInstance("SHA1PRNG");
                if (secureRandom == null)
                    throw new CSRFTokenGenerationException(
                            "Failed to get preferred SecureRandom provider");
            } catch (NoSuchAlgorithmException nsaEx) {
                throw new CSRFTokenGenerationException(
                        "Failed to generate CSRFToken using preferred SecureRandom", nsaEx);
            }
        }
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);

        String tokenValue = DatatypeConverter.printBase64Binary(randomBytes);
        //  Store the token object using the token storage service. Include context with it on client side
        //  for processing token during validation so we do not lose this information.
        StoredToken storedToken = new StoredToken(
                tokenValue,
                url,
                isOneTimeUseToken ? null : tokenTimeout,
                userSeed,
                isOneTimeUseToken,
                new Date().getTime());

        tokenStorageService.getTokenContextStore().setItem(storedToken.getTokenValue(), storedToken);

        return tokenValue;
    }


    /**
     * Retrieves the site wide CSRF token using the token storage service. Returns <code>null</code> if it does
     * not exist.
     *
     * @return  Site wide CSRF token, or <code>null</code> if one does not exist.
     */
    @Override
    public String getToken() {
        return getToken(null);
    }


    /**
     * Retrieves the CSRF token associated with the specified URL using the token storage service. Returns
     * <code>null</code> if it does not exist.
     *
     * @return  CSRF token associated with the given URL, or <code>null</code> if it does not exist.
     */
    @Override
    public String getToken(String url) {
        String csrfToken = null;

        //  Get the token context in the HttpSession and scan it for the token associated with the URL.
        CSRFTokenContextStore tokenContextStore = tokenStorageService.getTokenContextStore();
        if (tokenContextStore != null) {
            //null URL will return the site wide CSRF token, if it exists, or null
            StoredToken storedToken = tokenContextStore.getStoredToken(url);
            csrfToken = storedToken != null ? storedToken.getTokenValue() : null;
        }

        if (StringUtils.isBlank(csrfToken))
            csrfToken = null;
        return csrfToken;
    }


    /**
     * Validates the specified CSRF token against the token context store. All tokenSpecs details supplied
     * in the argument are validated. Tokens supplied for exempt URLs always validate to <code>true</code>. One
     * time use tokens are removed from the token context store once retrieved. Token verification
     * can fail if:
     * <ul>
     *     <li>Token does not exist in the token context store</li>
     *     <li>Token does not match token in <code>HttpServletRequest</code></li>
     *     <li>User identity exists for token in store and does not match identity in token context's user context</li>
     *     <li>Token has expired</li>
     *     <li>URL for request context does not match URL for token in context store</li>
     * </ul>
     *
     * @param token         token to be verified.
     * @param tokenContext  token verification context according to which the token is to be validated.
     * @return              <code>True</code> if token verification succeeds.
     * @throws CSRFTokenVerificationException
     */
    @Override
    public boolean verifyToken(String token, TokenVerificationContext tokenContext)
            throws CSRFTokenVerificationException {

        if (tokenContext != null) {
            //  If the rule for this token is null, it is associated with an exempt URL, in which
            //  case the token verification returns true. Else, the rule will hold a possible token
            //  timeout value.
            CSRFResourceProtectionRule protectionRule = tokenContext.getResourceProtectionRule();
            if (protectionRule == null) {
                logger.warn(
                        "Exempted URL encountered");
                return true;
            }
        }

        if (StringUtils.isBlank(token)) {
            logger.warn(
                    "Request token is empty");
            return false;
        }
        if (!checkToken(token)) {
            logger.warn(
                    "Invalid token format");
            return false;
        }

        CSRFUserContext userContext = (tokenContext != null ? tokenContext.getUserContext() : null);
        CSRFRequestContext requestContext = (tokenContext != null ? tokenContext.getRequestContext() : null);
        CSRFTokenContextStore tokenContextStore = tokenStorageService.getTokenContextStore();
        // Get the token object in the HttpSession that contains the input token to ensure it was previously
        // generated.
        StoredToken storedToken = tokenContextStore.getItem(token);

        if (storedToken == null) {
            logger.warn(
                    "Stored token is not available");
            return false;
        }

        //  Get the token from the request context, HttpServletRequest, and match against the input token.
        String requestToken = (requestContext != null ? requestContext.getRequestToken() : null);
        if (requestToken != null) {
            if (!StringUtils.equals(token, requestToken)) {
                logger.warn(
                        "Request token does not match stored token. ");
                return false;
            }
        }

        //  Match the user identity from the token store and request context.
        String tokenUser = storedToken.getUserIdentifier();
        String requestUser = (userContext != null ? userContext.getUserIdentifier() : null);
        if (tokenUser != null) {
            if (requestUser == null) {
                logger.warn(
                        "Found user-issued token but verification " +
                                "request is missing user identifier. ");
                return false;
            }
            if (!StringUtils.equals(requestUser, tokenUser)) {
                logger.warn(
                        "Issued token user does not match request user. ");
                return false;
            }
        }

        //  Match the token in the token context store and the input.
        String expectedToken = storedToken.getTokenValue();
        if (!SecureCompare.isEqual(token.getBytes(), expectedToken.getBytes())) {
            logger.warn(
                    "Encountered error performing token validation. ");
            return false;
        }

        //  Verify token has not expired by comparing the token creation timestamp and any supplied timeout.
        Long tokenTimestamp = storedToken.getTokenTimestamp();
        Long tokenTimeout = storedToken.getTokenTimeout();
        if (tokenTimestamp != null && tokenTimeout != null
                && TokenHelper.timestampIsExpired(tokenTimestamp, tokenTimeout)) {
            logger.warn(
                    "CSRF Token is expired: ");

            return false;
        }

        //  If validating token for a specific URL, verify URL associated with token in context store and
        //  URL from request context.
        String issuedTokenURL = storedToken.getResourceURL();
        String requestTokenURL = (requestContext != null ? requestContext.getRequestURL() : null);
        if (StringUtils.isNotBlank(issuedTokenURL)) {
            if (StringUtils.isBlank(requestTokenURL)) {
                logger.warn(
                        "Found url-issued token but verification " +
                                "request is missing url information. ");
                return false;
            }
            if (!StringUtils.equals(issuedTokenURL, requestTokenURL)) {
                logger.warn(
                        "Issued token url does not match request url. ");
                return false;
            }
        }

        if (storedToken.isOneTimeUseToken()) {  //  Remove one time use tokens from the session store.
            tokenContextStore.removeItem(token);
            logger.debug("Removed one time use token from store");
        }
        logger.debug(
                "Request token and stored token matches. " );
        return true;
    }

    private boolean checkToken(String token) {
        if (token == null || token.length() != 44) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (!(Character.isAlphabetic(c) || Character.isDigit(c) || '+' == c || '/' == c || '=' == c)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Throws {@link CSRFTokenServiceException} as storage based token service does not support user identities.
     *
     * @throws CSRFTokenServiceException    when attempting to set user seed for a protection strategy that does not
     *                                      define user identities.
     */
    @Override
    public void setUserSeed(String userSeed)
            throws CSRFTokenServiceException {
        throw new CSRFTokenServiceException(
                "User seeds are not defined for session based CSRF Protection");
    }

    /**
     * Throws {@link CSRFTokenServiceException} as storage based token service does not support default timeout values.
     *
     * @throws CSRFTokenServiceException    when attempting to set the default timeout for a protection strategy that
     *                                      does not use default token timeouts.
     */
    @Override
    public void setDefaultTimeout(Long defaultTokenTimeout)
            throws CSRFTokenServiceException {
        throw new CSRFTokenServiceException(
                "Default timeouts are not defined for session based CSRF Protection");
    }

}
