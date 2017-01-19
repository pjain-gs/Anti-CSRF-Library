
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

import com.gdssecurity.anticsrf.spi.rules.CSRFResourceExemptionRule;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesException;
import org.apache.commons.lang3.StringUtils;

import java.util.regex.Pattern;

/**
 * Rule governing a URL's exemption properties.
 */
public class PatternExemptionRule implements CSRFResourceExemptionRule, PatternRule {

    // Any URL that is not exempt is associated with a NULL_RULE.
    static final PatternExemptionRule NULL_RULE = new PatternExemptionRule();

    private final String resourceURLPatternString;
    private final Pattern resourceURLPattern;


    /**
     * Default constructor for the exemption rule.
     */
    private PatternExemptionRule() {
        this.resourceURLPatternString = null;
        this.resourceURLPattern = null;
    }

    /**
     * Creates an exemption rule for the specified URL.
     * @param resourceURLPattern    URL for which to create an exemption rule.
     * @throws CSRFRulesException   if a failure occurs while compiling the given URL into a pattern.
     */
    PatternExemptionRule(String resourceURLPattern) {
        this.resourceURLPatternString = StringUtils.trim(resourceURLPattern);

        try {
            this.resourceURLPattern = Pattern.compile(resourceURLPatternString);
        } catch (Exception ex) {
            throw new CSRFRulesException(
                    "Failed to compile CSRF exemption rule" +
                            " with resource URL pattern: " + resourceURLPatternString, ex);
        }
    }

    /**
     * Gets the URL associated with this exemption rule.
     * @return  URL associated with exemption rule.
     */
    @Override
    public String getResourceURL() {
        return resourceURLPatternString;
    }

    /**
     * <code>Pattern</code> URL was compiled into for this exemption rule.
     * @return  <code>Pattern</code> for URL.
     */
    @Override
    public Pattern getResourceURLPattern() {
        return resourceURLPattern;
    }


    @Override
    public String toString() {
        return ("(Exemption Rule: '" + resourceURLPatternString + "')");
    }

}
