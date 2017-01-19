
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

package com.gdssecurity.anticsrf.core.logging;

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingServiceFactory;

/**
 * Factory class that creates the default logging service.
 */
public final class DefaultCSRFLoggingServiceFactory implements CSRFLoggingServiceFactory {

    // Only create one logging service for the protection service
    private static CSRFLoggingService loggingService;

    /**
     * Gets the logging service instance.
     *
     * @return  instance of the logging service.
     */
    @Override
    public CSRFLoggingService getLoggingService(CSRFConfigService configService) {
        if (loggingService != null) {
            return loggingService;
        }
        // Synchronize access so we only create one logging service instance
        synchronized (DefaultCSRFLoggingServiceFactory.class) {
            if (loggingService == null) {
                loggingService = new DefaultCSRFLoggingService();
            }
        }
        return loggingService;
    }

}
