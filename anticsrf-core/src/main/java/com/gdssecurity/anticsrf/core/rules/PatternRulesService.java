
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

package com.gdssecurity.anticsrf.core.rules;

import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesService;

import java.util.List;

/**
 * Rules service implementing <code>CSRFRulesService</code> to manage protection and exemption rules according to
 * which tokens will be validated.
 */
public class PatternRulesService implements CSRFRulesService {

    private final List<PatternProtectionRule> protectionRules;
    private final List<PatternExemptionRule> exemptionRules;

    // Cache list of rules checked for URLs to speed up retrieval.
    private final RulesCache<PatternProtectionRule> protectionRulesCache;
    private final RulesCache<PatternExemptionRule> exemptionRulesCache;

    private final CSRFLoggingService loggingService;


    PatternRulesService(
            List<PatternProtectionRule> protectionRules,
            List<PatternExemptionRule> exemptionRules,
            CSRFLoggingService loggingService) {

        this.protectionRules = protectionRules;
        this.exemptionRules = exemptionRules;
        this.protectionRulesCache = new RulesCache<PatternProtectionRule>();
        this.exemptionRulesCache = new RulesCache<PatternExemptionRule>();
        this.loggingService = loggingService;
    }

    /**
     * Gets the protection rule for the URL specified in the request context as specified in the configuration file.
     * Returns <code>null</code> if the specified URL is an exempt URL. Returns the default protection rule if there are
     * no protection rules associated with this URL.
     *
     * @param requestContext    request context to parse for URL to check for associated protection rules.
     * @return                  Protection rule determined from the configuration file that is associated with the given
     *                          request context.Returns <code>null</code> for an exempt request. Returns the default protection
     *                          rule if there are no protection rules associated with this request context.
     */
    @Override
    public PatternProtectionRule getProtectionRuleForRequest(CSRFRequestContext requestContext) {
        return getProtectionRuleForResource(requestContext.getRequestURL());
    }

    /**
     * Gets the protection rule for the specified resource URL as specified in the configuration file. Returns
     * <code>null</code> if the specified URL is an exempt URL. Returns the default protection rule if there are no
     * protection rules associated with this URL.
     *
     * @param resourceURL   request context to parse for URL to check for associated protection rules.
     * @return              Protection rule determined from the configuration file that is associated with the given URL.
     *                      Returns <code>null</code> for an exempt URL. Returns the default protection rule if there are
     *                      no protection rules associated with this URL.
     */
    @Override
    public PatternProtectionRule getProtectionRuleForResource(String resourceURL) {
        // Check if this URL's rule has already been cached.
        PatternProtectionRule rule = protectionRulesCache.get(resourceURL);

        if (rule == null) {
            // Check if the URL is an exempt URL and set to null if it is. If not, find or compile its associated protection
            // rule and cache it for future use.
            if (!isExemptResource(resourceURL)) {
                rule = RulesHelper.findRuleForResource(resourceURL, protectionRules);
                if (rule == null) // There is no protection for this URL, so create the default rule for it.
                    rule = PatternProtectionRule.NULL_RULE;
            }
            protectionRulesCache.put(resourceURL, rule);
        }

        return rule;
    }

    /**
     * Returns <code>true</code> if the specified resource URL is configured as exempt in the configuration file.
     *
     * @param resourceURL   resource URL to check for exemption.
     * @return              <code>True</code> if the given URL is specified as an exempt resource in the configuration file.
     */
    @Override
    public boolean isExemptResource(String resourceURL) {
        return (getExemptionRuleForResource(resourceURL) == null);
    }

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
    @Override
    public PatternExemptionRule getExemptionRuleForResource(String resourceURL) {
        // Check if this URL's rule has already been cached.
        PatternExemptionRule rule = exemptionRulesCache.get(resourceURL);

        if (rule == null) {
            // Check if the URL is an exempt URL. If not, find or compile its associated exemption
            // rule and cache it for future use.
            rule = RulesHelper.findRuleForResource(resourceURL, exemptionRules);
            // Rule will be null if it is not exempt, so set it as a NULL_RULE.
            if (rule == null) {
                rule = PatternExemptionRule.NULL_RULE;
            }
            // Cache this URL's exemption rule.
            exemptionRulesCache.put(resourceURL, rule);
        }
        // If this URL is exempt and does not need token validation, return null.
        return (rule == PatternExemptionRule.NULL_RULE ? rule : null);
    }


}
