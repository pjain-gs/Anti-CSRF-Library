
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

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionService;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionServiceFactory;

/**
 * Factory class for the default CSRF protection service
 */
public class DefaultCSRFProtectionServiceFactory implements CSRFProtectionServiceFactory {

    /**
     * Gets the protection service instance.
     * @param configService the configuration service for managing protection
     *                      service initialization.
     * @return              instance of the protection service.
     */
    @Override
    public CSRFProtectionService createCSRFProtectionService(CSRFConfigService configService) {
        return CSRFProtectionUtil.createProtectionService(configService);
    }

}
