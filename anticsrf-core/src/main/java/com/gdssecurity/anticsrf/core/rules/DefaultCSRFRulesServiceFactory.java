
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

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesService;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesServiceFactory;

import java.util.List;

/**
 * Factory class that creates the default rules service.
 */
public class DefaultCSRFRulesServiceFactory implements CSRFRulesServiceFactory {

    private static CSRFRulesService rulesService;

    /**
     * Gets the rules service instance.
     *
     * @param configService     the configuration service to manage rules service initialization.
     * @param loggingService    the logging facility.
     * @return                  instance of the rules service.
     */
    @Override
    public CSRFRulesService getCSRFRulesService(CSRFConfigService configService, CSRFLoggingService loggingService) {
        if (rulesService != null) {
            return rulesService;
        }
        // Synchronize access as we only require one instance of the rules service for the entire protection service.
        synchronized (this) {
            if (rulesService == null) {
                List<PatternExemptionRule> exemptionRules = RulesHelper.getExemptionRules(
                        configService.getExemptUrlEntries());

                List<PatternProtectionRule> protectionRules = RulesHelper.getProtectionRules(
                        configService.getUrlSpecificRuleEntries(),
                        configService.getDefaultTokenTimeout());

                // Create a new rules service containing all protection rules and exemption rules.
                rulesService = new PatternRulesService(protectionRules, exemptionRules, loggingService);
            }
        }
        return rulesService;
    }
}
