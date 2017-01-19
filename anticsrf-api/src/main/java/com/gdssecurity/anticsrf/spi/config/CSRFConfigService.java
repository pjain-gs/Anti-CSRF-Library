
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

package com.gdssecurity.anticsrf.spi.config;

import java.util.List;
import java.util.Map;

/**
 * Interface for any class that implements a configuration service. All user-defined configuration
 * values and inputs can be read through these interface methods
 */
public interface CSRFConfigService {

    /* --- Factories --- */

    /**
     * Returns the name of the CSRF Protection Service Factory class.
     *
     * @return  Name of the CSRF Protection Service Factory class.
     */
    public String getCSRFProtectionServiceFactoryClass();

    /**
     * Returns the name of the CSRF Rules Service Factory class.
     *
     * @return  Name of the CSRF Rules Service Factory class.
     */
    public String getCSRFRulesServiceFactoryClass();

    /**
     * Returns the name of the CSRF Token Service Factory class.
     *
     * @return  Name of the CSRF Token Service Factory class.
     */
    public String getCSRFTokenServiceFactoryClass();

    /**
     * Returns the name of the CSRF Signing Service Factory class.
     *
     * @return  Name of the CSRF Signing Service Factory class.
     */
    public String getCSRFSigningServiceFactoryClass();

    /**
     * Returns the name of the CSRF Token Storage Service Factory class.
     *
     * @return  Name of the CSRF Token Storage Service Factory class.
     */
    public String getCSRFTokenStorageServiceFactoryClass();

    /**
     * Returns the name of the CSRF Request Context Factory class.
     *
     * @return  Name of the CSRF Request Context Factory class.
     */
    public String getCSRFRequestContextFactoryClass();

    /**
     * Returns the name of the CSRF User Context Factory class.
     *
     * @return  Name of the CSRF User Context Factory class.
     */
    public String getCSRFUserContextFactoryClass();

    /**
     * Returns the name of the CSRF Logging Service Factory class.
     *
     * @return  Name of the CSRF Logging Service Factory class.
     */
    public String getCSRFLoggingServiceFactoryClass();
    
    
    /* --- Specific Configs --- */

    /**
     * Returns the token parameter name, as specified in the configuration file, that is used as a request parameter
     * used to pass the token in requests.
     *
     * @return  Token parameter name, as specified in the configuration file.
     */
    public String getTokenParameterName();

    /**
     * Returns the request attribute name, as specified in the configuration file, that is used when storing tokens within
     * the HttpServletRequest object.
     *
     * @return  Request attribute name, as specified in the configuration file.
     */
    public String getRequestAttributeName();

    /**
     * Returns the session attribute name, as specified in the configuration file, that is used when storing tokens within
     * the HttpSession object.
     *
     * @return  Session attribute name, as specified in the configuration file.
     */
    public String getSessionAttributeName();

    /**
     * Returns the HTTP header name, as specified in the configuration file, that is used when storing tokens within
     * a request header.
     *
     * @return  HTTP header name name, as specified in the configuration file.
     */
    public String getSessionCSRFHeader();

    /**
     * Returns the default token timeout, as specified in the configuration file, that is the default timeout value used
     * for site wide CSRF tokens. Any token older than the specified value will be denied.
     *
     * @return  Default token timeout, as specified in the configuration file.
     */
    public Long getDefaultTokenTimeout();

    /**
     * Returns the token recollection strategy, as deduced from the protection mode in the configuration file, that is
     * used when creating the default CSRF protection service.
     *
     * @return  Token recollection strategy, as deduced from the protection mode in the configuration file.
     */
    public String getTokenRecollectionStrategy();

    /**
     * Returns the path to the file containing the HMAC signing key, as specified in the configuration file.
     *
     * @return  Path to the file containing the HMAC signing key, as specified in the configuration file.
     */
    public String getTokenSigningKeyPath();

    /**
     * Returns a list of URLs that will have a unique token, valid for only that URL, and its associated timeout value,
     * as specified in the configuration file.
     *
     * @return  List of URLs that will have a unique token, valid for only that URL, and its associated timeout value,
     *          as specified in the configuration file.
     */
    public List<Map.Entry<String, Long>> getUrlSpecificRuleEntries();

    /**
     * Returns a list of URLs that will be marked as exempt from token validation, as specified in the configuration file.
     *
     * @return  List of URLs that will be marked as exempt from token validation, as specified in the configuration file.
     */
    public List<String> getExemptUrlEntries();
    
    
    /* --- Generic Config Values --- */

    /**
     * Returns the value associated with the specified property name, as specified in the configuration file.
     *
     * @param propertyName  property name whose associated value is to be returned.
     * @return              The value to which the specified property name is paired
     */
    public String getCustomConfigValue(String propertyName);

}