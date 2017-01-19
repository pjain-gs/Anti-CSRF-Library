
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

package com.gdssecurity.anticsrf.core.config;

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Map;

/**
 * Adapter configuration service class that implements the <code>CSRFConfigService</code> and contains a <code>CSRFConfig</code> object
 */
class CSRFConfigAdapterConfigService implements CSRFConfigService {

    private final CSRFConfig config;

    /**
     * Initializes the configuration object used by the service class to configure the behavior of the protection
     * strategy
     *
     * @param config    configuration object that contains all properties parsed from the configuration file and
     *                  names of default factory classes
     */
    CSRFConfigAdapterConfigService(CSRFConfig config) {
        this.config = config;
    }

    /**
     * Gets name of CSRF protection service factory responsible for facilitating the CSRF prevention strategy.
     *
     * @return  Name of protection service factory class.
     */
    @Override
    public String getCSRFProtectionServiceFactoryClass() {
        return config.getCSRFProtectionServiceFactoryClass();
    }

    /**
     * Gets name of CSRF rules service factory class used to process the protection rules associated with the <code>HttpServletRequest</code>.
     *
     * @return  Name of rules service factory class.
     */
    @Override
    public String getCSRFRulesServiceFactoryClass() {
        return config.getCSRFRulesServiceFactoryClass();
    }

    /**
     * Gets name of CSRF token service factory class used to facilitate token generation and validation based on
     * the token recollection strategy.
     *
     * @return  Name of token service factory class.
     */
    @Override
    public String getCSRFTokenServiceFactoryClass() {
        return config.getCSRFTokenServiceFactoryClass();
    }

    /**
     *  Gets name of CSRF signing service factory class responsible for token signing and verification
     *  when using HMAC based protection
     *
     * @return  Name of signing service factory class.
     */
    @Override
    public String getCSRFSigningServiceFactoryClass() {
        return config.getCSRFSigningServiceFactoryClass();
    }

    /**
     *  Gets name of CSRF token storage service factory class responsible for storing all currently valid token
     *  contexts when using session based protection
     *
     * @return  Name of token storage service factory class.
     */
    @Override
    public String getCSRFTokenStorageServiceFactoryClass() {
        return config.getCSRFTokenStorageServiceFactoryClass();
    }

    /**
     *  Gets name of CSRF request context factory class used to facilitate processing of the <code>HttpServletRequest</code>.
     *
     * @return  Name of request context factory class.
     */
    @Override
    public String getCSRFRequestContextFactoryClass() {
        return config.getCSRFRequestContextFactoryClass();
    }

    /**
     *  Gets name of CSRF user context factory class used to manage the user identity.
     *
     * @return  Name of user context factory class.
     */
    @Override
    public String getCSRFUserContextFactoryClass() {
        return config.getCSRFUserContextFactoryClass();
    }

    /**
     *  Gets name of CSRF logging service factory class used to provide core logging capabilities.
     *
     * @return  Name of logging service factory class.
     */
    @Override
    public String getCSRFLoggingServiceFactoryClass() {
        return config.getCSRFLoggingServiceFactoryClass();
    }

    /**
     * Gets the request parameter name used to pass the CSRF Token in requests, as specified in the configuration
     * file.
     *
     * @return  Request parameter name specified in the configuration file.
     */
    @Override
    public String getTokenParameterName() {
        return config.getTokenParameterName();
    }

    /**
     *  Gets the request attribute name used when storing tokens within the <code>HttpServletRequest</code> object, as
     *  specified in the configuration file.
     *
     * @return  Request attribute name specified in the configuration file.
     */
    @Override
    public String getRequestAttributeName() {
        return config.getRequestAttributeName();
    }

    /**
     *  Gets the session attribute name used to store the token context store object.
     *
     * @return  Session attribute name where token context store is located.
     */
    @Override
    public String getSessionAttributeName() {
        return config.getSessionAttributeName();
    }

    /**
     * Gets the HTTP header name used to pass the CSRF Token in requests, as specified in the configuration
     * file.
     *
     * @return  HTTP header name specified in the configuration file.
     */
    @Override
    public String getSessionCSRFHeader() {
        return config.getSessionCSRFHeader();
    }

    /**
     *  Gets the timeout value (in minutes) for site wide CSRF tokens and URL specific tokens with no designated
     *  timeout value. This value is specified in the configuration file and is for HMAC based protection only.
     *
     * @return  Timeout value for site wide CSRF tokens and URL specific tokens without a specified timeout value
     *          used in HMAC based protection.
     */
    @Override
    public Long getDefaultTokenTimeout() {
        return config.getDefaultTokenTimeout();
    }

    /**
     *  Gets the token recollection strategy, determined from the protection mode specified in the configuration
     *  file, that is being used by the protection service.
     *
     * @return  Name of token recollection strategy being used by the protection service.
     */
    @Override
    public String getTokenRecollectionStrategy() {
        return config.getTokenRecollectionStrategy();
    }

    /**
     *  Gets the file path to the key file containing the HMAC signing key, as specified in the configuration file.
     *
     * @return  Path to key file specified in the configuration file that contains the HMAC signing key.
     */
    @Override
    public String getTokenSigningKeyPath() {
        return config.getEncryptionKeyPath();
    }

    /**
     *  Gets a list of URLs that that will have a unique token, valid only for that URL, as specified in the configuration file.
     *
     * @return  List of URLs specified in the configuration file that require unique tokens.
     */
    @Override
    public List<Map.Entry<String, Long>> getUrlSpecificRuleEntries() {
        return config.getUrlSpecificRuleEntries();
    }

    /**
     *  Gets a list of URLs that will be marked as exempt from token validation, as specified in the configuration file.
     *
     * @return  List of exempt URLs specified in the configuration file.
     */
    @Override
    public List<String> getExemptUrlEntries() {
        return config.getExemptUrlEntries();
    }

    /**
     *  Gets a custom value specified in the configuration file via the specified configuration property.
     *
     * @param configProperty    custom key used in configuration file to map custom value.
     * @return                  Custom value specified in the configuration value using specified configuration property.
     */
    @Override
    public String getCustomConfigValue(String configProperty) {
        if (StringUtils.isBlank(configProperty)) {
            return null;
        }
        return config.getCustomConfigValue(configProperty);
    }

}
