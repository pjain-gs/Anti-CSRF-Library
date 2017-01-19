
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

import com.gdssecurity.anticsrf.spi.rules.CSRFResourceProtectionRule;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesException;
import org.apache.commons.lang3.StringUtils;

import java.util.regex.Pattern;

/**
 * Rule governing a URL's protection properties, including any token timeout value.
 */
public class PatternProtectionRule implements CSRFResourceProtectionRule, PatternRule {

    // Any URL that has no protection rules is associated with a NULL_RULE.
    static final PatternProtectionRule NULL_RULE = new PatternProtectionRule();

    private final String resourceURLPatternString;
    private final Pattern resourceURLPattern;
    private final Long tokenTimeout;


    /**
     * Default constructor for the protection rule.
     */
    private PatternProtectionRule() {
        this.resourceURLPatternString = null;
        this.resourceURLPattern = null;
        this.tokenTimeout = null;
    }

    /**
     * Creates a protection rule for the specified URL with the optional token timeout.
     * @param resourceURLPattern    URL for which to create an exemption rule.
     * @param tokenTimeout          Optional token timeout for the given URL.
     * @throws CSRFRulesException   if a failure occurs while compiling the given URL into a pattern.
     */
    public PatternProtectionRule(String resourceURLPattern, Long tokenTimeout) {
        this.resourceURLPatternString = StringUtils.trim(resourceURLPattern);
        this.tokenTimeout = tokenTimeout;

        try {
            this.resourceURLPattern = Pattern.compile(resourceURLPatternString);
        } catch (Exception ex) {
            throw new CSRFRulesException(
                    "Failed to compile CSRF protection rule" +
                            " with resource URL pattern: " + resourceURLPattern, ex);
        }
    }

    /**
     * Gets the URL associated with this protection rule.
     * @return URL associated with protection rule.
     */
    @Override
    public String getResourceURL() {
        return resourceURLPatternString;
    }

    /**
     * <code>Pattern</code> URL was compiled into for this protection rule.
     * @return  <code>Pattern</code> for URL.
     */
    @Override
    public Pattern getResourceURLPattern() {
        return resourceURLPattern;
    }

    /**
     * Gets the token timeout associated with this protection rule.
     * @return  Token timeout associated with protection rule.
     */
    @Override
    public Long getTokenTimeout() {
        return tokenTimeout;
    }


    @Override
    public String toString() {
        return ("(Protection Rule: '" + resourceURLPatternString + " : " + tokenTimeout + " ms')");
    }

}
