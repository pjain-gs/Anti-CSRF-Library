
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

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;


public class RulesHelper {

    private static final Logger log = Logger.getLogger(RulesHelper.class.getName());

    /**
     * Creates a list of all pattern protection rules parsed from the configuration file.
     *
     * @param protectionRuleEntries     map with specific URL and associated timeout value entries from configuration file.
     * @param defaultTokenTimeoutMsecs  default token timeout for site wide tokens, or URL specific tokens without
     *                                  a designated timeout value.
     * @return                          List of {@link PatternProtectionRule} created for all URL specific
     *                                  entries in the configuration file.
     */
    static List<PatternProtectionRule> getProtectionRules(
            List<Map.Entry<String, Long>> protectionRuleEntries,
            Long defaultTokenTimeoutMsecs) {

        List<PatternProtectionRule> protectionRules = new ArrayList<PatternProtectionRule>();

        if (protectionRuleEntries != null)
            for (Map.Entry<String, Long> ruleEntry : protectionRuleEntries) {
                String urlExpression = ruleEntry.getKey();
                if (StringUtils.isBlank(urlExpression)) {
                    log.warning("Skipped provided URL-specific protection entry with blank expression");
                    continue;
                }
                Long tokenValidityMsecs = ruleEntry.getValue();

                protectionRules.add(new PatternProtectionRule(urlExpression, tokenValidityMsecs));
            }
        return protectionRules;
    }

    /**
     * Creates a list of all pattern exemption rules parsed from the configuration file.
     *
     * @param exemptionRuleEntries  list with all exempt URLs from configuration file.
     * @return                      List of {@link PatternExemptionRule} created for all exempt
     *                              URL entries in the configuration file.
     */
    static List<PatternExemptionRule> getExemptionRules(List<String> exemptionRuleEntries) {
        List<PatternExemptionRule> exemptionRules = new ArrayList<PatternExemptionRule>();

        if (exemptionRuleEntries != null)
            for (String exemptionRuleEntry : exemptionRuleEntries) {
                if (StringUtils.isBlank(exemptionRuleEntry)) {
                    log.warning("Skipped provided blank URL exemption entry");
                    continue;
                }
                exemptionRules.add(new PatternExemptionRule(exemptionRuleEntry));
            }
        return exemptionRules;
    }

    /**
     * Finds the corresponding pattern rule for the specified URL from the given rules list, or <code>null</code> if
     * it does not exist.
     *
     * @param resourceURL   URL for which to find associated pattern rule.
     * @param rulesList     rules list containing subset of pattern rules created from the configuration file.
     * @param <T>           rule type to find.
     * @return              {@link PatternRule} associated with specified URL, or <code>null</code> if one does not exist.
     */
    static <T extends PatternRule> T findRuleForResource(String resourceURL, List<T> rulesList) {
        if (StringUtils.isBlank(resourceURL) || rulesList == null) {
            return null;
        }

        for (T rule : rulesList) {
            if (rule == null) {
                continue;
            }
            if (rule.getResourceURLPattern()
                    .matcher(resourceURL)
                    .matches()) {
                return rule;
            }
        }
        return null;
    }

}
