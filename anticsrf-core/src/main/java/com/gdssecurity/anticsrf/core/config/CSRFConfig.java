
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

import java.util.*;

/**
 * This class contains all properties parsed from the configuration file and names of default factory classes
 */
public final class CSRFConfig {

    // All service and context factory classes names are stored in the config object.
    private String csrfConfigServiceFactoryClass;
    private String csrfProtectionServiceFactoryClass;
    private String csrfRulesServiceFactoryClass;
    private String csrfTokenServiceFactoryClass;
    private String csrfSigningServiceFactoryClass;
    private String csrfTokenStorageServiceFactoryClass;
    private String csrfRequestContextFactoryClass;
    private String csrfUserContextFactoryClass;
    private String csrfLoggingServiceFactoryClass;

    // These properties are parsed from the configuration file and control the protection strategy behavior.
    private String tokenParameterName;
    private String requestAttributeName;
    private String sessionAttributeName;
    private String sessionCSRFHeader;
    private Long defaultTokenTimeout;
    private String tokenRecollectionStrategy;
    private String encryptionKeyPath;

    // Lists of all protection rules and exemption rules, and the corresponding URL parsed from the configuration file.
    private final List<Map.Entry<String, Long>> protectionRules;
    private final List<String> exemptionRules;

    // Map of any custom configurations in the configuration file
    private final Map<String, String> customConfigs;

    /**
     * Constructor initializing class lists and maps.
     */
    CSRFConfig() {
        this.protectionRules = new ArrayList<Map.Entry<String, Long>>();
        this.exemptionRules = new ArrayList<String>();
        this.customConfigs = new HashMap<String, String>();
    }

    /**
     * Gets name of the CSRF config service factory class used to configure the behavior of the protection strategy.
     *
     * @return Name of config service factory class.
     */
    public String getCSRFConfigServiceFactoryClass() {
        return csrfConfigServiceFactoryClass;
    }

    /**
     * Gets name of CSRF protection service factory responsible for facilitating the CSRF prevention strategy.
     *
     * @return  Name of protection service factory class.
     */
    public String getCSRFProtectionServiceFactoryClass() {
        return csrfProtectionServiceFactoryClass;
    }

    /**
     * Gets name of CSRF rules service factory class used to process the protection rules associated with the <code>HttpServletRequest</code>.
     *
     * @return  Name of rules service factory class.
     */
    public String getCSRFRulesServiceFactoryClass() {
        return csrfRulesServiceFactoryClass;
    }

    /**
     * Gets name of CSRF token service factory class used to facilitate token generation and validation based on
     * the token recollection strategy.
     *
     * @return  Name of token service factory class.
     */
    public String getCSRFTokenServiceFactoryClass() {
        return csrfTokenServiceFactoryClass;
    }

    /**
     *  Gets name of CSRF signing service factory class responsible for token signing and verification
     *  when using HMAC based protection
     *
     * @return  Name of signing service factory class.
     */
    public String getCSRFSigningServiceFactoryClass() {
        return csrfSigningServiceFactoryClass;
    }

    /**
     *  Gets name of CSRF token storage service factory class responsible for storing all currently valid token
     *  contexts when using session based protection
     *
     * @return  Name of token storage service factory class.
     */
    public String getCSRFTokenStorageServiceFactoryClass() {
        return csrfTokenStorageServiceFactoryClass;
    }

    /**
     *  Gets name of CSRF request context factory class used to facilitate processing of the <code>HttpServletRequest</code>.
     *
     * @return  Name of request context factory class.
     */
    public String getCSRFRequestContextFactoryClass() {
        return csrfRequestContextFactoryClass;
    }

    /**
     *  Gets name of CSRF user context factory class used to manage the user identity.
     *
     * @return  Name of user context factory class.
     */
    public String getCSRFUserContextFactoryClass() {
        return csrfUserContextFactoryClass;
    }

    /**
     *  Gets name of CSRF logging service factory class used to provide core logging capabilities.
     *
     * @return  Name of logging service factory class.
     */
    public String getCSRFLoggingServiceFactoryClass() {
        return csrfLoggingServiceFactoryClass;
    }

    /**
     * Gets the request parameter name used to pass the CSRF Token in requests, as specified in the configuration
     * file.
     *
     * @return  Request parameter name specified in the configuration file.
     */
    public String getTokenParameterName() {
        return tokenParameterName;
    }

    /**
     *  Gets the request attribute name used when storing tokens within the <code>HttpServletRequest</code> object, as
     *  specified in the configuration file.
     *
     * @return  Request attribute name specified in the configuration file.
     */
    public String getRequestAttributeName() {
        return requestAttributeName;
    }

    /**
     *  Gets the session attribute name used to store the token context store object.
     *
     * @return  Session attribute name where token context store is located.
     */
    public String getSessionAttributeName() {
        return sessionAttributeName;
    }

    /**
     * Gets the HTTP header name used to pass the CSRF Token in requests, as specified in the configuration
     * file.
     *
     * @return  HTTP header name specified in the configuration file.
     */
    public String getSessionCSRFHeader() {
        return sessionCSRFHeader;
    }

    /**
     *  Gets the timeout value (in minutes) for site wide CSRF tokens and URL specific tokens with no designated
     *  timeout value. This value is specified in the configuration file and is for HMAC based protection only.
     *
     * @return  Timeout value for site wide CSRF tokens and URL specific tokens without a specified timeout value
     *          used in HMAC based protection.
     */
    public Long getDefaultTokenTimeout() {
        return defaultTokenTimeout;
    }

    /**
     *  Gets the token recollection strategy, determined from the protection mode specified in the configuration
     *  file, that is being used by the protection service.
     *
     * @return  Name of token recollection strategy being used by the protection service.
     */
    public String getTokenRecollectionStrategy() {
        return tokenRecollectionStrategy;
    }

    /**
     * Gets the file path to the key file containing the HMAC signing key, as specified in the configuration file.
     *
     * @return  Path to key file specified in the configuration file that contains the HMAC signing key.
     */
    public String getEncryptionKeyPath() {
        return encryptionKeyPath;
    }

    /**
     * Gets a list of URLs that that will have a unique token, valid only for that URL, as specified in the configuration file.
     *
     * @return  List of URLs specified in the configuration file that require unique tokens.
     */
    public List<Map.Entry<String, Long>> getUrlSpecificRuleEntries() {
        return Collections.unmodifiableList(protectionRules);
    }

    /**
     * Gets a list of URLs that will be marked as exempt from token validation, as specified in the configuration file.
     *
     * @return  List of exempt URLs specified in the configuration file.
     */
    public List<String> getExemptUrlEntries() {
        return Collections.unmodifiableList(exemptionRules);
    }

    /**
     * Gets a custom value specified in the configuration file via the specified configuration property.
     *
     * @param configProperty    custom key used in configuration file to map custom value.
     * @return                  Custom value specified in the configuration value using specified configuration property.
     */
    public String getCustomConfigValue(String configProperty) {
        return customConfigs.get(configProperty);
    }


    /**
     * Gets a builder for a {@link CSRFConfig} or {@link CSRFConfigService}.
     */
    public static Builder builder() {
        return new Builder();
    }


    /**
     * Returns a {@link CSRFConfigService} backed by this {@link CSRFConfig} instance.
     */
    public CSRFConfigService createService() {
        return new CSRFConfigAdapterConfigService(this);
    }
    
    
    /*
     * =============
     * BUILDER CLASS
     * =============
     */

    /**
     * Builder sets all the properties obtained from the config file in the CSRFConfig object
     */
    public static final class Builder {

        // Configuration object that will be instantiated with a call to build()
        private CSRFConfig config;

        private Builder() {
            this.config = new CSRFConfig();
        }


        public Builder setCSRFProtectionServiceFactoryClass(String csrfProtectionServiceFactoryClass) {
            config.csrfProtectionServiceFactoryClass = csrfProtectionServiceFactoryClass;
            return this;
        }


        public Builder setCSRFConfigServiceFactoryClass(String csrfConfigServiceFactoryClass) {
            config.csrfConfigServiceFactoryClass = csrfConfigServiceFactoryClass;
            return this;
        }


        public Builder setCSRFRulesServiceFactoryClass(String rulesServiceFactoryClass) {
            config.csrfRulesServiceFactoryClass = rulesServiceFactoryClass;
            return this;
        }


        public Builder setCSRFTokenServiceFactoryClass(String csrfTokenServiceFactoryClass) {
            config.csrfTokenServiceFactoryClass = csrfTokenServiceFactoryClass;
            return this;
        }


        public Builder setCSRFRequestContextFactoryClass(String csrfRequestContextFactoryClass) {
            config.csrfRequestContextFactoryClass = csrfRequestContextFactoryClass;
            return this;
        }


        public Builder setCSRFUserContextFactoryClass(String csrfUserContextFactoryClass) {
            config.csrfUserContextFactoryClass = csrfUserContextFactoryClass;
            return this;
        }


        public Builder setCSRFSignerFactoryClass(String csrfSignerFactoryClass) {
            config.csrfSigningServiceFactoryClass = csrfSignerFactoryClass;
            return this;
        }


        public Builder setCSRFTokenStorageServiceFactoryClass(String tokenStorageServiceFactoryClass) {
            config.csrfTokenStorageServiceFactoryClass = tokenStorageServiceFactoryClass;
            return this;
        }


        public Builder setCSRFLoggingServiceFactoryClass(String csrfLoggingServiceFactoryClass) {
            config.csrfLoggingServiceFactoryClass = csrfLoggingServiceFactoryClass;
            return this;
        }


        public Builder setTokenParameterName(String tokenParameterName) {
            config.tokenParameterName = tokenParameterName;
            return this;
        }


        public Builder setRequestAttributeName(String requestAttributeName) {
            config.requestAttributeName = requestAttributeName;
            return this;
        }


        public Builder setSessionAttributeName(String sessionAttributeName) {
            config.sessionAttributeName = sessionAttributeName;
            return this;
        }

        public Builder setSessionCSRFHeader(String sessionCSRFHeader) {
            config.sessionCSRFHeader = sessionCSRFHeader;
            return this;
        }

        public Builder setDefaultTokenTimeout(Long defaultTokenTimeout) {
            config.defaultTokenTimeout = defaultTokenTimeout;
            return this;
        }

        public Builder setTokenRecollectionStrategy(String tokenRecollectionStrategy) {
            config.tokenRecollectionStrategy = tokenRecollectionStrategy;
            return this;
        }


        public Builder setEncryptionKeyPath(String encryptionKeyPath) {
            config.encryptionKeyPath = encryptionKeyPath;
            return this;
        }


        public Builder addProtectionRule(Map.Entry<String, Long> protectionRule) {
            config.protectionRules.add(protectionRule);
            return this;
        }


        public Builder addProtectionRules(List<Map.Entry<String, Long>> protectionRules) {
            config.protectionRules.addAll(protectionRules);
            return this;
        }


        public Builder addExemptionRule(String exemptionRule) {
            config.exemptionRules.add(exemptionRule);
            return this;
        }


        public Builder addExemptionRules(List<String> exemptionRules) {
            config.exemptionRules.addAll(exemptionRules);
            return this;
        }


        public Builder setCustomConfigValue(String configProperty, String value) {
            config.customConfigs.put(configProperty, value);
            return this;
        }


        public Builder setCustomConfigValues(Map<String, String> customConfigs) {
            config.customConfigs.putAll(customConfigs);
            return this;
        }


        /**
         * Returns a {@link CSRFConfig} representing the built values and resets
         * the builder state so that a subsequent call to {@link #build()} will
         * only capture built values since the last call to the method.
         */
        public CSRFConfig build() {
            synchronized (this) {
                CSRFConfig builtConfig = this.config;
                this.config = new CSRFConfig();
                return builtConfig;
            }
        }
    }

}
