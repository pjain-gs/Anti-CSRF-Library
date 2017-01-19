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

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContextFactory;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContextService;

/**
 * Factory class to create the service managing the request context.
 */
public class J2EECSRFRequestContextFactory implements CSRFRequestContextFactory {

    /**
     * Gets the request context service with which to parse the <code>HttpServletRequest</code>.
     *
     * @param configService     the configuration service to manage request context service initialization.
     * @param loggingService    the logging facility.
     * @return                  {@link J2EERequestContextService} managing the request context.
     */
    @Override
    public CSRFRequestContextService getCSRFRequestContextService(
            CSRFConfigService configService,
            CSRFLoggingService loggingService) {

        return new J2EERequestContextService(configService.getTokenParameterName(), loggingService);
    }

}
