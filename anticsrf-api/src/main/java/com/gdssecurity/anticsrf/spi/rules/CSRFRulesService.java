
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

package com.gdssecurity.anticsrf.spi.rules;

import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;

/**
 * Interface for any class that implements a rules service used in processing protection rules for
 * a request context
 */
public interface CSRFRulesService {
    
    /* --- Protection --- */

    /**
     * Gets the protection rule for the specified resource URL as specified in the configuration file. Returns
     * <code>null</code> if the specified URL is an exempt URL. Returns the default protection rule if there are no
     * protection rules associated with this URL.
     *
     * @param resourceURL   resource URL to check for associated protection rules.
     * @return              Protection rule determined from the configuration file that is associated with the given URL.
     *                      Returns <code>null</code> for an exempt URL. Returns the default protection rule if there are
     *                      no protection rules associated with this URL.
     */
    public CSRFResourceProtectionRule getProtectionRuleForResource(String resourceURL);

    /**
     * Gets the protection rule for the URL specified in the request context as specified in the configuration file.
     * Returns <code>null</code> if the specified URL is an exempt URL. Returns the default protection rule if there are
     * no protection rules associated with this URL.
     *
     * @param requestContext    request context to parse for URL and check for associated protection rules.
     * @return                  Protection rule determined from the configuration file that is associated with the given
     *                          request context.Returns <code>null</code> for an exempt request. Returns the default protection
     *                          rule if there are no protection rules associated with this request context.
     */
    public CSRFResourceProtectionRule getProtectionRuleForRequest(CSRFRequestContext requestContext);

    /* --- Exemption --- */

    /**
     * Returns <code>true</code> if the specified resource URL is configured as exempt in the configuration file.
     *
     * @param resourceURL   resource URL to check for exemption.
     * @return              <code>True</code> if the given URL is specified as an exempt resource in the configuration file.
     */
    public boolean isExemptResource(String resourceURL);

    /**
     * Gets the exemption rule for the specified resource URL as specified in the configuration file. Returns
     * <code>null</code> if the specified URL is an exempt URL. Returns the default exemption rule if this is not
     * an exempt URL.
     *
     * @param resourceURL   resource URL to check for exemption.
     * @return              Exemption rule determined from the configuration file that is associated with the given URL.
     *                      Returns <code>null</code> for an exempt URL. Returns the default exemption rule if this is
     *                      not an exempt URL.
     */
    public CSRFResourceExemptionRule getExemptionRuleForResource(String resourceURL);

}
