
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

package com.gdssecurity.anticsrf.spi.user;

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;

/**
 * Factory class that gets the user context service used to manage the user identity
 */
public interface CSRFUserContextFactory {

    /**
     * Gets the user context service as configured by the configuration service.
     *
     * @param configService     the interface to the configuration service to manage user context service initialization.
     * @param loggingService    the interface to the logging facility.
     * @return                  {@link CSRFUserContextService} that facilitates processing of the client's user identity.
     */
    public CSRFUserContextService getCSRFUserContextService(
            CSRFConfigService configService, CSRFLoggingService loggingService);

}
