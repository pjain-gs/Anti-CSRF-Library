
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

package com.gdssecurity.anticsrf.impl.j2ee;

import com.gdssecurity.anticsrf.core.api.store.CSRFTokenStorageService;
import com.gdssecurity.anticsrf.core.api.store.CSRFTokenStorageServiceFactory;
import com.gdssecurity.anticsrf.impl.j2ee.util.J2EECSRFConstants;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import org.apache.commons.lang3.StringUtils;

/**
 * Factory class that creates the token storage service for J2EE session based protection
 */
public class J2EESessionTokenStorageServiceFactory implements CSRFTokenStorageServiceFactory {

    /**
     * Gets the token storage service as configured by the configuration service.
     *
     * @param configService                 the interface to the configuration service managing token storage
     *                                      service initialization.
     * @return                              {@link CSRFTokenStorageService} that manages session based token contexts.
     */
    @Override
    public CSRFTokenStorageService getCSRFTokenStorageService(CSRFConfigService configService) {
        String sessionStoreKey = configService.getSessionAttributeName();

        if (StringUtils.isBlank(sessionStoreKey)) {
            sessionStoreKey = J2EECSRFConstants.DEFAULT_SESSION_ATTRIBUTE_NAME;
        }
        return new J2EESessionTokenStorageService(sessionStoreKey);
    }

}
