
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

import java.util.List;
import java.util.Map.Entry;

/**
 * Abstract wrapper class to provide default behavior for a CSRF config service object
 */
public abstract class CSRFConfigServiceWrapper implements CSRFConfigService {

    private final CSRFConfigService configService;

    /**
     * Initializes the configuration service object used to configure the behavior of the protection
     * strategy
     *
     * @param configService     configuration service object that reads all properties parsed from the configuration file and
     *                          names of default factory classes
     */
    public CSRFConfigServiceWrapper(CSRFConfigService configService) {
        this.configService = configService;
    }

    /**
     * Gets name of CSRF protection service factory responsible for facilitating the CSRF prevention strategy.
     *
     * @return  Name of protection service factory class.
     */
    public String getCSRFProtectionServiceFactoryClass() {
        return configService.getCSRFProtectionServiceFactoryClass();
    }

    /**
     * Gets name of CSRF rules service factory class used to process the protection rules associated with the <code>HttpServletRequest</code>.
     *
     * @return  Name of rules service factory class.
     */
    public String getCSRFRulesServiceFactoryClass() {
        return configService.getCSRFRulesServiceFactoryClass();
    }

    /**
     * Gets name of CSRF token service factory class used to facilitate token generation and validation based on
     * the token recollection strategy.
     *
     * @return  Name of token service factory class.
     */
    public String getCSRFTokenServiceFactoryClass() {
        return configService.getCSRFTokenServiceFactoryClass();
    }

    /**
     *  Gets name of CSRF signing service factory class responsible for token signing and verification
     *  when using HMAC based protection
     *
     * @return  Name of signing service factory class.
     */
    public String getCSRFSigningServiceFactoryClass() {
        return configService.getCSRFSigningServiceFactoryClass();
    }

    /**
     *  Gets name of CSRF token storage service factory class responsible for storing all currently valid token
     *  contexts when using session based protection
     *
     * @return  Name of token storage service factory class.
     */
    public String getCSRFTokenStorageServiceFactoryClass() {
        return configService.getCSRFTokenStorageServiceFactoryClass();
    }

    /**
     *  Gets name of CSRF request context factory class used to facilitate processing of the <code>HttpServletRequest</code>.
     *
     * @return  Name of request context factory class.
     */
    public String getCSRFRequestContextFactoryClass() {
        return configService.getCSRFRequestContextFactoryClass();
    }

    /**
     *  Gets name of CSRF user context factory class used to manage the user identity.
     *
     * @return  Name of user context factory class.
     */
    public String getCSRFUserContextFactoryClass() {
        return configService.getCSRFUserContextFactoryClass();
    }

    /**
     *  Gets name of CSRF logging service factory class used to provide core logging capabilities.
     *
     * @return  Name of logging service factory class.
     */
    public String getCSRFLoggingServiceFactoryClass() {
        return configService.getCSRFLoggingServiceFactoryClass();
    }

    /**
     * Gets the request parameter name used to pass the CSRF Token in requests, as specified in the configuration
     * file.
     *
     * @return  Request parameter name specified in the configuration file.
     */
    public String getTokenParameterName() {
        return configService.getTokenParameterName();
    }

    /**
     *  Gets the request attribute name used when storing tokens within the <code>HttpServletRequest</code> object, as
     *  specified in the configuration file.
     *
     * @return  Request attribute name specified in the configuration file.
     */
    public String getRequestAttributeName() {
        return configService.getRequestAttributeName();
    }

    /**
     *  Gets the session attribute name used to store the token context store object.
     *
     * @return  Session attribute name where token context store is located.
     */
    public String getSessionAttributeName() {
        return configService.getSessionAttributeName();
    }

    /**
     * Gets the HTTP header name used to pass the CSRF Token in requests, as specified in the configuration
     * file.
     *
     * @return  HTTP header name specified in the configuration file.
     */
    public String getSessionCSRFHeader() {
        return configService.getSessionCSRFHeader();
    }

    /**
     *  Gets the timeout value (in minutes) for site wide CSRF tokens and URL specific tokens with no designated
     *  timeout value. This value is specified in the configuration file and is for HMAC based protection only.
     *
     * @return  Timeout value for site wide CSRF tokens and URL specific tokens without a specified timeout value
     *          used in HMAC based protection.
     */
    public Long getDefaultTokenTimeout() {
        return configService.getDefaultTokenTimeout();
    }

    /**
     *  Gets the token recollection strategy, determined from the protection mode specified in the configuration
     *  file, that is being used by the protection service.
     *
     * @return  Name of token recollection strategy being used by the protection service.
     */
    public String getTokenRecollectionStrategy() {
        return configService.getTokenRecollectionStrategy();
    }

    /**
     *  Gets the file path to the key file containing the HMAC signing key, as specified in the configuration file.
     *
     * @return  Path to key file specified in the configuration file that contains the HMAC signing key.
     */
    public String getTokenSigningKeyPath() {
        return configService.getTokenSigningKeyPath();
    }

    /**
     *  Gets a list of URLs that that will have a unique token, valid only for that URL, as specified in the configuration file.
     *
     * @return  List of URLs specified in the configuration file that require unique tokens.
     */
    public List<Entry<String, Long>> getUrlSpecificRuleEntries() {
        return configService.getUrlSpecificRuleEntries();
    }

    /**
     *  Gets a list of URLs that will be marked as exempt from token validation, as specified in the configuration file.
     *
     * @return  List of exempt URLs specified in the configuration file.
     */
    public List<String> getExemptUrlEntries() {
        return configService.getExemptUrlEntries();
    }

    /**
     *  Gets a custom value specified in the configuration file via the specified configuration property.
     *
     * @param configProperty    custom key used in configuration file to map custom value.
     * @return                  Custom value specified in the configuration value using specified configuration property.
     */
    public String getCustomConfigValue(String propertyName) {
        return configService.getCustomConfigValue(propertyName);
    }

}
