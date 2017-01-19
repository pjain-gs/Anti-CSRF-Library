
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

package com.gdssecurity.anticsrf.core.protection;

import com.gdssecurity.anticsrf.core.config.CSRFConfigUtil;
import com.gdssecurity.anticsrf.core.util.CSRFFactoryException;
import com.gdssecurity.anticsrf.core.util.CSRFFactoryUtil;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionException;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionService;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContextService;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesService;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenService;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContextService;

/**
 * Utility class to create the CSRF protection service
 */
final class CSRFProtectionUtil {

    /**
     * Creates the protection service instance.
     *
     * @param csrfConfigService         configuration service instance to use to manage behavior of protection service.
     * @return                          {@CSRFProtectionService} instance.
     * @throws CSRFProtectionException  if a failure occurred during creation of the CSRF protection service instance.
     */
    static CSRFProtectionService createProtectionService(CSRFConfigService csrfConfigService)
            throws CSRFProtectionException {

        CSRFProtectionService service = createService(csrfConfigService);

        return service;
    }

    /**
     * Helper method to create the protection service instance.
     *
     * @param csrfConfigService         configuration service instance to use to manage behavior of protection service.
     * @return                          {@CSRFProtectionService} instance.
     * @throws CSRFProtectionException  if a failure occurred during creation of the CSRF protection service instance.
     */
    protected static CSRFProtectionService createService(CSRFConfigService csrfConfigService)
            throws CSRFProtectionException {

        try {
            // Need a configuration service instance to be able to create the protection service.
            CSRFConfigService configService = (csrfConfigService != null
                    ? csrfConfigService
                    : CSRFConfigUtil.getConfigServiceFactory().getCSRFConfigService());
            // Obtain all underlying services used by the protection service.
            CSRFLoggingService loggingService = CSRFProtectionHelper.getCSRFLoggingService(configService);
            CSRFRulesService rulesService = CSRFProtectionHelper.getCSRFRulesService(configService, loggingService);
            CSRFTokenService tokenService = CSRFProtectionHelper.getCSRFTokenService(configService, loggingService);

            CSRFRequestContextService requestContextService =
                    CSRFProtectionHelper.getCSRFRequestContextService(configService, loggingService);

            CSRFUserContextService userContextService =
                    CSRFProtectionHelper.getCSRFUserContextService(configService, loggingService);

            // Create and initialize the protection service.
            CSRFProtectionService protectionService = CSRFFactoryUtil.create(
                    null,
                    CSRFProtectionService.class,
                    DefaultCSRFProtectionService.class,
                    configService);

            protectionService.init(
                    tokenService,
                    rulesService,
                    requestContextService,
                    userContextService,
                    configService,
                    loggingService);

            return protectionService;
        } catch (CSRFFactoryException ex) {
            throw new CSRFProtectionException("Failed to create protection service", ex);
        }
    }

}
