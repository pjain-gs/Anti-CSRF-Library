
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

package com.gdssecurity.anticsrf.core.tokens;

import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningService;
import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningServiceException;
import com.gdssecurity.anticsrf.core.api.store.CSRFTokenStorageException;
import com.gdssecurity.anticsrf.core.api.store.CSRFTokenStorageService;
import com.gdssecurity.anticsrf.core.api.store.CSRFTokenStorageServiceFactory;
import com.gdssecurity.anticsrf.core.tokens.signing.CSRFSigningServiceUtil;
import com.gdssecurity.anticsrf.core.util.CSRFFactoryException;
import com.gdssecurity.anticsrf.core.util.CSRFFactoryUtil;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenService;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenServiceException;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenServiceFactory;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * Factory class for the default CSRF token service
 */
public class DefaultCSRFTokenServiceFactory implements CSRFTokenServiceFactory {

    /**
     * Gets the token service as configured by the configuration service.
     *
     * @param configService                 the configuration service to manage token service initialization.
     * @param loggingService                the logging facility.
     * @return                              {@link CSRFTokenService} that generates and validates tokens.
     * @throws CSRFTokenServiceException    if a failure occurs during creation of the token service.
     */
    @Override
    public CSRFTokenService getCSRFTokenService(
            CSRFConfigService configService,
            CSRFLoggingService loggingService) {

        CSRFTokenRecollectionStrategy tokenRecollectionStrategy = EnumUtils.getEnum(
                CSRFTokenRecollectionStrategy.class, configService.getTokenRecollectionStrategy());

        // As the default mode used by the configuration loader is session based, the token recollection
        // strategy will also be session based by default.
        tokenRecollectionStrategy = (tokenRecollectionStrategy != null ?
                tokenRecollectionStrategy
                : CSRFTokenRecollectionStrategy.TOKEN_STORAGE);

        switch (tokenRecollectionStrategy) {

            case TOKEN_SIGNING:
                // Create the signing service in case of TOKEN_SIGNING recollection.
                try {
                    CSRFSigningService signingService = CSRFSigningServiceUtil
                            .getCSRFSigningServiceFactory(configService)
                            .getCSRFSigningService(configService, loggingService);

                    return new SigningBasedCSRFTokenService(signingService, loggingService);
                } catch (CSRFSigningServiceException ex) {
                    throw new CSRFTokenServiceException(
                            "Error while acquiring CSRF signing service for" +
                                    " token-signing CSRF protection service", ex);
                }

            case TOKEN_STORAGE:
                // Create the token storage service in case of TOKEN_STORAGE recollection.
                String tokenStorageServiceFactoryClassName = configService.getCSRFTokenStorageServiceFactoryClass();

                try {
                    if (StringUtils.isBlank(tokenStorageServiceFactoryClassName)) {
                        throw new CSRFTokenServiceException(
                                "No token storage service factory class specified" +
                                        " for token storage recollection strategy");
                    }
                    CSRFTokenStorageServiceFactory tokenStorageServiceFactory = CSRFFactoryUtil.create(
                            tokenStorageServiceFactoryClassName,
                            CSRFTokenStorageServiceFactory.class,
                            null,
                            configService);

                    CSRFTokenStorageService tokenStorageService = (tokenStorageServiceFactory != null
                            ? tokenStorageServiceFactory.getCSRFTokenStorageService(configService)
                            : null);

                    if (tokenStorageService == null) {
                        throw new CSRFTokenServiceException(
                                "Failed to acquire token storage service" +
                                        " for token-storage token recollection strategy" +
                                        " using factory class " + tokenStorageServiceFactoryClassName);
                    }
                    // Create the session based token service that utilizes the token storage service.
                    return new StoreBasedCSRFTokenService(tokenStorageService, loggingService);
                } catch (CSRFFactoryException ex) {
                    throw new CSRFTokenServiceException(
                            "Failed to acquire token storage service factory for CSRF protection service." +
                                    " Factory class = " + tokenStorageServiceFactoryClassName, ex);
                } catch (CSRFTokenStorageException ex) {
                    throw new CSRFTokenServiceException(
                            "Failed to acquire token storage service from factory", ex);
                }
        }

        throw new CSRFTokenServiceException(
                "No factory specified or available for CSRF Protection Service.");
    }
}
