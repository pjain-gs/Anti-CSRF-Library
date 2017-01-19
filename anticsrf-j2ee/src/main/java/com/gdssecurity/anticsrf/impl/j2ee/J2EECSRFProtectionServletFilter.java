
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

import com.gdssecurity.anticsrf.CSRFProtection;
import com.gdssecurity.anticsrf.core.config.CSRFConfigUtil;
import com.gdssecurity.anticsrf.core.tokens.CSRFTokenRecollectionStrategy;
import com.gdssecurity.anticsrf.core.util.Constants;
import com.gdssecurity.anticsrf.impl.j2ee.util.J2EECSRFConstants;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLogger;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionException;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionService;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Filter for session based token synchronization or HMAC based CSRF protection
 */
public class J2EECSRFProtectionServletFilter implements Filter {

    private static final Logger logger = Logger.getLogger(J2EECSRFProtectionServletFilter.class.getName());

    private CSRFProtectionService protectionService;
    private CSRFConfigService configService;
    private CSRFLogger csrfLogger;
    private String tokenParamName;  //  Request parameter used to pass CSRF tokens in Http requests.

    private Pattern csrfTokenLeadParamPattern;  //  Compiled regex to strip lead CSRF token from URL.
    private Pattern csrfTokenTailParamPattern;  //  Compiled regex to strip tail CSRF token from URL.


    /**
     * Initializes the filter. Loads the configuration, sets up the logger, and creates the specified protection
     * service.
     *
     * @param filterConfig      used to pass information to filter during initialization.
     * @throws ServletException if a failure occurred during filter initialization.
     */
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        logger.info("The J2EECSRFProtectionServletFilter is initializing");

        //  Get configuration file path.
        String configFile = filterConfig.getInitParameter(J2EECSRFConstants.FILTER_INIT_PARAM_CSRF_CONFIG_FILE);

        if (configFile == null) {
            configFile = filterConfig.getServletContext()
                    .getRealPath("/WEB-INF/" + J2EECSRFConstants.CONFIG_FILE_NAME);

            logger.info(
                    "No Filter init-param set for AntiCSRF config file. " +
                            "Using default: " + configFile);
        } else {
            logger.info(
                    "AntiCSRF Configuration init-param specified. " +
                            "Configuration file set to " + configFile);
        }

        CSRFConfigUtil.setConfigFile(configFile);
        CSRFConfigService configServiceFromFile = CSRFConfigUtil.getConfigServiceFactory().getCSRFConfigService();  //  Use the loaded configuration properties to create the configuration service.
        CSRFConfigService configService = new J2EECSRFConfigServiceWrapper(configServiceFromFile);   //  Creates config service specific to J2EE apps.

        //  Initialize the protection service using the configuration service to manage behavior.
        CSRFProtectionService protectionService = CSRFProtection
                .createDefaultCSRFProtectionServiceFactory()
                .createCSRFProtectionService(configService);

        J2EEProtectionServiceHolder.setService(protectionService);  //  Store the protection service for use in JSP taglib.

        this.protectionService = protectionService;
        this.csrfLogger = protectionService.getLoggingService().getLogger(this);
        this.configService = protectionService.getConfigService();
        this.tokenParamName = configServiceFromFile.getTokenParameterName();

        this.csrfTokenLeadParamPattern = Pattern.compile("(" + tokenParamName + "=([^\\s\\?&]+)?[&])");
        this.csrfTokenTailParamPattern = Pattern.compile("[\\?&](" + tokenParamName + "=([^\\s\\?&]+)?)");
    }

    /**
     * Verifies the tokens match OR generates a token if one does not exist
     *
     * @param req               <code>HttpServletRequest</code> providing information about request variables.
     * @param res               <code>HttpServletResponse</code> providing HTTP-specific functionality in sending a response
     *                          to a client.
     * @param chain             provides a mechanism for invoking a series of filters
     * @throws ServletException if an unexpected failure occurred.
     * @throws IOException
     */
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        try {

            // Store request in servlet context (ThreadLocal) to be used in validation step.
            J2EEServletContext.bindContext(request);

            logRequestUrlWithoutToken(request);

            J2EECSRFRequestContext reqContext = ensureAttributeAndGetRequestContext();

            if (!getBooleanConfigValue(J2EECustomConfig.MONITOR_MODE.configKey()))
            {
                boolean isVerifiedRequest = false;

                try {
                    // Verify the request token stored in the request parameter.
                    isVerifiedRequest = protectionService
                            .isVerifiedRequest(reqContext, null);
                } catch (CSRFProtectionException ex) {
                    csrfLogger.warn("Failed while validating request against CSRF", ex);
                } catch (Exception ex) {
                    csrfLogger.warn("Unknown failure while validating request against CSRF", ex);
                }

                // If MonitorMode is disabled, we handle the invalid CSRF token
                // validation error. Otherwise, we continue normal execution.
                if (!isVerifiedRequest) {
                    handleError(request, response);
                    return;
                }

            }
            chain.doFilter(request, response);
        } finally {
            J2EEServletContext.unbindContext();
        }
    }

    private J2EECSRFRequestContext ensureAttributeAndGetRequestContext() {
        //  Create request context object to parse HttpServletRequest.
        J2EECSRFRequestContext reqContext = new J2EECSRFRequestContext(tokenParamName);
        String storedCSRFToken;

        //  Determine token recollection strategy from configuration properties. If null, set to TOKEN_STORAGE.
        CSRFTokenRecollectionStrategy tokenRecollectionStrategy = EnumUtils.getEnum(
                CSRFTokenRecollectionStrategy.class, configService.getTokenRecollectionStrategy());
        // Default strategy is session based.
        if (tokenRecollectionStrategy == null)
            tokenRecollectionStrategy = CSRFTokenRecollectionStrategy.TOKEN_STORAGE;

        switch (tokenRecollectionStrategy) {
            case TOKEN_SIGNING:
                // If HMAC mode, lets add a new token to the request attribute first.
                // This will allow for a rolling timestamp on the CSRFToken.

                // Provide the HMAC protection service with the user identifier that is used in hashing the token.
                protectionService.setUserSeed(getUserSeed());

                // Provide the HMAC service the default timeout value from the filter because it can't access configuration values.
                protectionService.setDefaultTimeout(configService.getDefaultTokenTimeout());

                if (protectionService.hasUrlSpecificConfig(reqContext.getRequestURL()))
                    storedCSRFToken = protectionService.generateResourceToken(reqContext.getRequestURL(), null);
                else
                    storedCSRFToken = protectionService.generateToken();

                J2EEServletContext.getRequest().setAttribute(
                        configService.getRequestAttributeName(), storedCSRFToken);
                break;
            default:
                // If Session, the token will be valid across the whole life of the
                // session token. Therefore, we will only generate a new one if a Token
                // is not currently set within session.
                storedCSRFToken = protectionService.getToken(reqContext.getRequestURL());
                if (storedCSRFToken == null || storedCSRFToken.equals("")) {
                    storedCSRFToken = protectionService.hasUrlSpecificConfig(reqContext.getRequestURL()) ?
                            protectionService.generateResourceToken(reqContext.getRequestURL(), null) :
                            protectionService.generateToken();
                }
                J2EEServletContext.getRequest().setAttribute(
                        configService.getRequestAttributeName(), storedCSRFToken);
                break;
        }
        return reqContext;
    }


    private void logRequestUrlWithoutToken(HttpServletRequest request) {
        if (request == null) {
            return;
        }

        String adjustedURL = J2EEHelper.getRequestURL(request);

        adjustedURL = csrfTokenLeadParamPattern.matcher(adjustedURL).replaceFirst("");
        adjustedURL = csrfTokenTailParamPattern.matcher(adjustedURL).replaceFirst("");

        csrfLogger.info("The J2EECSRFProtectionServletFilter is running on URL: " + adjustedURL);
    }


    @Override
    public void destroy() {
                /* Nothing to do */
    }

    /**
     * Handles a failure in CSRF verification.
     *
     * @param request           <code>HttpServletRequest</code> providing information about request variables.
     * @param response          <code>HttpServletResponse</code> providing HTTP-specific functionality in sending a response
     *                          to a client.
     * @throws IOException
     * @throws ServletException if an unexpected failure occurred.
     */
    protected void handleError(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
		/*
		 * Check if the request is an XMLHTTPRequest/AJAX request
		 */
        if (configService.getCustomConfigValue(J2EECustomConfig.AJAX_ERROR.configKey()) != null) {
            if (request.getHeader("X-Requested-With") != null
                    && request.getHeader("X-Requested-With").equals("XMLHttpRequest")) {
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":{\"type\":\"invalid_csrf\"}");

                return;
            }
        }
		/*
		 * Token validation failed. Lets handle the error based on the config file
		 */
        String errorHandling = configService.getCustomConfigValue(J2EECustomConfig.ERROR_HANDLING_ACTION.configKey());
        String errorValue = configService.getCustomConfigValue(J2EECustomConfig.ERROR_HANDLING_VALUE.configKey());

        if (StringUtils.equalsIgnoreCase(errorHandling, "redirect")) {
            response.sendRedirect(errorValue);
        } else if (StringUtils.equalsIgnoreCase(errorHandling, "forward")) {
            RequestDispatcher dispatcher = request.getRequestDispatcher(errorValue);
            dispatcher.forward(request, response);
        } else if (StringUtils.equalsIgnoreCase(errorHandling, "status_code")) {
            int statusCode = Integer.parseInt(errorValue);
            response.sendError(statusCode, "Request failed");
        } else {
			/*
			 * No configuration, so send basic default error
			 */
            response.sendError(403, "Access Denied");
        }
    }


    /**
     * Gets the configuration boolean value for the specified key.
     *
     * @param configKey key to find mapped value for.
     * @return          Boolean value mapped to specified key.
     */
    protected boolean getBooleanConfigValue(String configKey) {
        return StringUtils.equalsIgnoreCase(
                configService.getCustomConfigValue(configKey),
                J2EECSRFConstants.CONF_VALUE_TRUE);
    }

    /**
     * Gets the user seed from the <code>HttpServletRequest</code>, or the default user seed if not passed
     * as an attribute.
     *
     * @return  User seed to use for HMAC based protection.
     */
    protected String getUserSeed() {

        String userSeed = (String) J2EEServletContext.getRequest().getAttribute(
                configService.getCustomConfigValue(Constants.CONF_HMAC_USERSEED_ATTR));

        if (userSeed == null) {
            String err = "User Seed not found in HttpServletRequest attribute. "
                    + "Defaulting to a generic user seed since we cannot tie the token to a user identity";
            csrfLogger.warn(err);
            return J2EECSRFConstants.DEFAULT_USERSEED;
        }

        return userSeed;
    }

}
