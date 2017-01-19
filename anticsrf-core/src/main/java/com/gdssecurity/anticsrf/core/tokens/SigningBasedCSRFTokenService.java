
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

import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningException;
import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningService;
import com.gdssecurity.anticsrf.core.util.StringUtil;
import com.gdssecurity.anticsrf.spi.logging.CSRFLogger;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.rules.CSRFResourceProtectionRule;
import com.gdssecurity.anticsrf.spi.tokens.*;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;
import org.apache.commons.lang3.StringUtils;

import java.util.Date;

/**
 * Signing service class implementing <code>CSRFTokenService</code>
 */
final class SigningBasedCSRFTokenService implements CSRFTokenService {

    private static final String HASHED_TOKEN_FIELD_DELIMITER = ":"; // Used to delimit string containing user seed, URL, and timeout.

    private final CSRFLogger logger;
    private final CSRFSigningService signingService;


    private String userSeed;    // Default user seed in case none is set.
    private Long defaultTokenTimeout;   // Default token timeout in case none is set.

    /**
     * Constructor to initialize signing token service.
     *
     * @param signingService    signing service object used to sign and verify tokens.
     * @param loggingService    logging facility used by the signing service.
     */
    SigningBasedCSRFTokenService(CSRFSigningService signingService, CSRFLoggingService loggingService) {
        this.signingService = signingService;
        this.logger = loggingService.getLogger(SigningBasedCSRFTokenService.class);
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
     * Generates a CSRF token according to the parameters specified by the token generation context and a timestamp.
     *
     * @param tokenContext                  specifications according to which the token is to be generated.
     * @return                              Generated CSRF token.
     * @throws CSRFTokenGenerationException if there is a problem generating the token.
     */
    @Override
    public String generateToken(CSRFTokenGenerationContext tokenContext)
            throws CSRFTokenGenerationException {

        CSRFResourceProtectionRule protectionRule = null;
        CSRFUserContext userContext = null;
        String url = null;
        Long tokenTimeout;
        String seed;

        if (tokenContext != null) { // Token context may be null for a site wide token.
            protectionRule = tokenContext.getResourceProtectionRule();
            userContext = tokenContext.getUserContext();
            url = tokenContext.getResourceURL();
        }

        tokenTimeout = protectionRule != null ?
                protectionRule.getTokenTimeout()
                : null;
        seed = userContext != null ?
                userContext.getUserIdentifier()
                : this.userSeed;
        // Create the unhashed token from the user seed, optional URL, and optional token timeout.
        String plainToken = TokenHelper.generatePlainTokenString(url, seed, tokenTimeout);

        // Add the timestamp to the hashed token to be later used in checking token expiration.
        try {
            String currentTimeString = String.valueOf(new Date().getTime());
            String hashedToken = signingService.sign(plainToken);

            return (hashedToken +
                    HASHED_TOKEN_FIELD_DELIMITER +
                    currentTimeString);
        } catch (CSRFSigningException ex) {
            throw new CSRFTokenGenerationException("Failed while signing token", ex);
        }
    }

    /**
     * Always returns <code>null</code> for signing based protection.
     *
     * @return  <code>null</code>.
     */
    @Override
    public String getToken() {
        return getToken(null);
    }

    /**
     * Always returns <code>null</code> for signing based protection.
     *
     * @return  <code>null</code>.
     */
    @Override
    public String getToken(String url) {
        return null;
    }

    /**
     * Validates the specified CSRF token according to the specified token verification context. All tokenSpecs details supplied
     * in the argument are considered. Tokens supplied for exempt URLs always validate to <code>true</code>. Token verification
     * can fail if:
     * <ul>
     *     <li>Input token and token generated from verification context do not match</li>
     *     <li>Input token does not contain the correct number of fields</li>
     *     <li>Input token is missing creation timestamp</li>
     *     <li>Input token has expired</li>
     * </ul>
     *
     * @param token                             token to be verified.
     * @param tokenContext                      token verification context according to which the token is
     *                                          to be validated.
     * @return                                  <code>True</code> if token verification succeeds.
     * @throws CSRFTokenVerificationException   if there is a problem verifying the token.
     */
    @Override
    public boolean verifyToken(String token, TokenVerificationContext tokenContext)
            throws CSRFTokenVerificationException {
        if (StringUtils.isBlank(token)) {
            throw new CSRFTokenVerificationException("CSRF token is blank.");
        }

        //  If the rule for this token is null, it is associated with an exempt URL, in which
        //  case the token verification returns true. Else, the rule will hold a possible token
        //  timeout value.
        CSRFResourceProtectionRule rule = tokenContext.getResourceProtectionRule();
        if (rule == null) {
            return true;
        }

        //  User context will hold the user seed.
        CSRFUserContext userContext = tokenContext.getUserContext();

        String url = tokenContext.getRequestContext().getRequestURL();
        String userSeed = userContext != null ?
                userContext.getUserIdentifier()
                : this.userSeed;
        Long tokenTimeout = (rule.getTokenTimeout() != null) ?
                rule.getTokenTimeout()
                : null;

        String plainToken = TokenHelper.generatePlainTokenString(url, userSeed, tokenTimeout);

        try {
            //  Ensure given token has the correct number of fields, i.e.
            //  <signed token from user seed, URL, timeout>:<signed timestamp value>

            String[] csrfTokenContents = token.split(HASHED_TOKEN_FIELD_DELIMITER);

            if (csrfTokenContents.length != 2) {
                throw new CSRFTokenVerificationException(
                        "Signed CSRF Token contains invalid number of delimited fields: " +
                                "userSeed = " + StringUtil.stripNewlines(userSeed) + ", " +
                                "submittedToken = " + StringUtil.stripNewlines(token));
            }

            String hashedToken = csrfTokenContents[0];
            String hashedTokenTimestampString = csrfTokenContents[1];

            Long hashedTokenTimestamp = (StringUtils.isNotBlank(hashedTokenTimestampString)
                    ? Long.valueOf(hashedTokenTimestampString)
                    : null);

            //  Use the plain token generated from the verification context and verify it matches
            //  the first field in the given hashed token. These two tokens are derived from URL, user seed, and
            //  token timeout value, which should be equivalent in both tokens.
            if (!signingService.verify(plainToken, hashedToken)) {
                logger.warn(
                        "CSRF Token did not contain a valid signature: " +
                                "userSeed = " + StringUtil.stripNewlines(userSeed) + ", " +
                                "submittedToken = " + StringUtil.stripNewlines(hashedToken));
                return false;
            }
            //  Use the hashed token creation timestamp to ensure the token is not expired. If no token
            //  timeout value was specified at token generation time, use the default timeout value to
            //  check for expiration.
            if (hashedTokenTimestamp == null) {
                logger.warn(
                        "CSRF token having timeout rule is missing creation timestamp: " +
                                "rule timeout = " + tokenTimeout + ", " +
                                "userSeed = " + StringUtil.stripNewlines(userSeed) + ", " +
                                "submittedToken = " + StringUtil.stripNewlines(token));
                return false;
            }
            if (TokenHelper.timestampIsExpired(hashedTokenTimestamp, tokenTimeout != null ? tokenTimeout : this.defaultTokenTimeout)) {
                logger.warn(
                        "CSRF Token is expired: " +
                                "token timestamp = " + hashedTokenTimestamp + ", " +
                                "rule timeout = " + (tokenTimeout != null ? tokenTimeout : this.defaultTokenTimeout) + ", " +
                                "userSeed = " + StringUtil.stripNewlines(userSeed) + ", " +
                                "submittedToken = " + StringUtil.stripNewlines(token));
                return false;
            }

            return true;
        } catch (NumberFormatException ex) {
            String errorMsg =
                    "SECURITY WARNING! - " +
                            "Timestamp submitted within CSRFToken is not in a valid format - " +
                            "This may be the result of a tampering attempt on the token timestamp." +
                            "userSeed=" + StringUtil.stripNewlines(userSeed) + ", " +
                            "submittedToken=" + StringUtil.stripNewlines(token);

            logger.warn(errorMsg, ex);
            throw new CSRFTokenVerificationException(errorMsg, ex);
        } catch (CSRFSigningException ex) {
            String errorMsg =
                    "SECURITY WARNING! - " +
                            "Encountered error performing signature validation - " +
                            "This may be the result of a tampering attempt on the token." +
                            "userSeed=" + StringUtil.stripNewlines(userSeed) + ", " +
                            "submittedToken=" + StringUtil.stripNewlines(token);

            logger.warn(errorMsg, ex);
            throw new CSRFTokenVerificationException(errorMsg, ex);
        }
    }

    /**
     * Sets the client supplied user seed value used in creation of the token signature, when one is not provided
     * in the token generation context, for HMAC based protection from the <code>HttpServletRequest</code> object attribute specified in the configuration file.
     * <p>
     * Seed value ties a token to a user identity. The seed need not be cryptographically hashed and can be any value
     * unique to the authenticated user. The user seed should ideally be set within the application's authentication
     * filter or module. This will allow for the user seed to be set consistently on all authenticated requests. A default
     * seed value will be used if one is not provided.
     *
     * @param userSeed  user seed value supplied by the client in the <code>HttpServletRequest</code> object.
     */
    @Override
    public void setUserSeed(String userSeed)
            throws CSRFTokenServiceException {
        this.userSeed = userSeed;
    }

    /**
     * Sets the default site wide token timeout to be used for HMAC based protection. Any token older than the specified value
     * will be denied. Default timeout value is 30 minutes.
     *
     * @param defaultTokenTimeout   timeout value, in minutes, for site wide tokens, or URL specific tokens without associated
     *                              timeouts.
     */
    @Override
    public void setDefaultTimeout(Long defaultTokenTimeout)
            throws CSRFTokenServiceException {
        this.defaultTokenTimeout = defaultTokenTimeout;
    }

}
