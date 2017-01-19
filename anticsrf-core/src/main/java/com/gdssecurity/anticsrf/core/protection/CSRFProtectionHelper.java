
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

import com.gdssecurity.anticsrf.core.logging.DefaultCSRFLoggingServiceFactory;
import com.gdssecurity.anticsrf.core.rules.DefaultCSRFRulesServiceFactory;
import com.gdssecurity.anticsrf.core.tokens.DefaultCSRFTokenServiceFactory;
import com.gdssecurity.anticsrf.core.util.CSRFFactoryUtil;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingServiceFactory;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContextFactory;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContextService;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesService;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesServiceFactory;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenService;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenServiceFactory;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContextFactory;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContextService;

/**
 * Helper class for CSRF protection service that creates instances for logging, rules, token, request
 * context, and user context
 */
class CSRFProtectionHelper {

    /**
     * Creates the CSRF logging service instance.
     *
     * @param configService     configuration service instance from which the logging service factory is obtained.
     * @return                  {@link CSRFLoggingService} instance.
     * @throws RuntimeException if a failure occurred during creation of the CSRF logging service factory.
     */
    static CSRFLoggingService getCSRFLoggingService(CSRFConfigService configService) {
        try {
            CSRFLoggingServiceFactory factory = CSRFFactoryUtil.create(
                    configService.getCSRFLoggingServiceFactoryClass(),
                    CSRFLoggingServiceFactory.class,
                    DefaultCSRFLoggingServiceFactory.class,
                    configService);

            return (factory != null
                    ? factory.getLoggingService(configService)
                    : null);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to acquire CSRF logging service factory", ex);
        }
    }

    /**
     * Creates the CSRF rules service instance.
     *
     * @param configService     configuration service instance from which the rules service factory is obtained.
     * @return                  {@link CSRFRulesService} instance.
     * @throws RuntimeException if a failure occurred during creation of the CSRF rules service factory.
     */
    static CSRFRulesService getCSRFRulesService(
            CSRFConfigService configService,
            CSRFLoggingService loggingService) {

        try {
            CSRFRulesServiceFactory factory = CSRFFactoryUtil.create(
                    configService.getCSRFRulesServiceFactoryClass(),
                    CSRFRulesServiceFactory.class,
                    DefaultCSRFRulesServiceFactory.class,
                    configService);

            return (factory != null
                    ? factory.getCSRFRulesService(configService, loggingService)
                    : null);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to acquire CSRF rules manager factory", ex);
        }
    }

    /**
     * Creates the CSRF token service instance.
     *
     * @param configService     configuration service instance from which the token service factory is obtained.
     * @return                  {@link CSRFTokenService} instance.
     * @throws RuntimeException if a failure occurred during creation of the CSRF token service factory.
     */
    static CSRFTokenService getCSRFTokenService(
            CSRFConfigService configService,
            CSRFLoggingService loggingService) {

        try {
            CSRFTokenServiceFactory factory = CSRFFactoryUtil.create(
                    configService.getCSRFTokenServiceFactoryClass(),
                    CSRFTokenServiceFactory.class,
                    DefaultCSRFTokenServiceFactory.class,
                    configService);

            return (factory != null
                    ? factory.getCSRFTokenService(configService, loggingService)
                    : null);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to acquire CSRF protection service factory", ex);
        }
    }

    /**
     * Creates the CSRF request context service instance.
     *
     * @param configService     configuration service instance from which the request context service factory is obtained.
     * @return                  {@link CSRFRequestContextService} instance.
     * @throws RuntimeException if a failure occurred during creation of the CSRF request context service factory.
     */
    static CSRFRequestContextService getCSRFRequestContextService(
            CSRFConfigService configService,
            CSRFLoggingService loggingService) {

        try {
            CSRFRequestContextFactory factory = CSRFFactoryUtil.create(
                    configService.getCSRFRequestContextFactoryClass(),
                    CSRFRequestContextFactory.class,
                    null,
                    configService);

            return (factory != null
                    ? factory.getCSRFRequestContextService(configService, loggingService)
                    : null);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to acquire CSRF request context factory", ex);
        }
    }

    /**
     * Creates the CSRF user context service instance.
     *
     * @param configService     configuration service instance from which the user context service factory is obtained.
     * @return                  {@link CSRFUserContextService} instance.
     * @throws RuntimeException if a failure occurred during creation of the CSRF user context service factory.
     */
    static CSRFUserContextService getCSRFUserContextService(
            CSRFConfigService configService,
            CSRFLoggingService loggingService) {

        try {
            CSRFUserContextFactory factory = CSRFFactoryUtil.create(
                    configService.getCSRFUserContextFactoryClass(),
                    CSRFUserContextFactory.class,
                    null,
                    configService);

            return (factory != null
                    ? factory.getCSRFUserContextService(configService, loggingService)
                    : null);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to acquire CSRF user context factory", ex);
        }
    }

}
