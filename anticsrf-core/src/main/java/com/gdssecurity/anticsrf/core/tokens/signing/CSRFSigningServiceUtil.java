
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

package com.gdssecurity.anticsrf.core.tokens.signing;

import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningServiceFactory;
import com.gdssecurity.anticsrf.core.util.CSRFFactoryException;
import com.gdssecurity.anticsrf.core.util.CSRFFactoryUtil;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;

/**
 * Utility class to create the CSRF signing service factory
 */
public class CSRFSigningServiceUtil {

    /**
     * Creates a signing service factory class.
     *
     * @param configService configuration service instance to use to manage signing service initialization..
     * @return                  {@link CSRFSigningServiceFactory} instance.
     * @throws RuntimeException if a failure occurred during creation of the signing service factory instance.
     */
    public static CSRFSigningServiceFactory getCSRFSigningServiceFactory(CSRFConfigService configService) {
        String factoryImplClassName = configService.getCSRFSigningServiceFactoryClass();

        CSRFSigningServiceFactory factory = null;

        try {
            factory = CSRFFactoryUtil.create(
                    factoryImplClassName,
                    CSRFSigningServiceFactory.class,
                    DefaultCSRFSigningServiceFactory.class,
                    configService);
        } catch (CSRFFactoryException ex) {
            throw new RuntimeException("Failed to acquire CSRF signing service factory", ex);
        }

        return factory;
    }

}
