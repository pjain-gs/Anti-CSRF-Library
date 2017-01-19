
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

package com.gdssecurity.anticsrf.spi.request;

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;

/**
 * Factory class that gets the request context service used to facilitate processing of the <code>HttpServletRequest</code>
 */
public interface CSRFRequestContextFactory {

    /**
     * Gets the request context service as configured by the configuration service.
     *
     * @param configService     the interface to the configuration service to manage request context service initialization.
     * @param loggingService    the interface to the logging facility.
     * @return                  {@link CSRFRequestContextService} that facilitates processing of the client request.
     */
    public CSRFRequestContextService getCSRFRequestContextService(
            CSRFConfigService configService, CSRFLoggingService loggingService);

}
