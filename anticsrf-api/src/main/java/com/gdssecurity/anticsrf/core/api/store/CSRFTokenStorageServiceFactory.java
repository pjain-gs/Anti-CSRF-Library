
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

package com.gdssecurity.anticsrf.core.api.store;

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;

/**
 * Factory class that gets the token storage service responsible for storing all currently valid token
 * contexts when using session based protection
 */
public interface CSRFTokenStorageServiceFactory {

    /**
     * Gets the token storage service as configured by the configuration service.
     *
     * @param configService                 the interface to the configuration service managing token storage
     *                                      service initialization.
     * @return                              {@link CSRFTokenStorageService} that manages session based token contexts.
     * @throws CSRFTokenStorageException    if a failure occurs during creation of the token storage service.
     */
    public CSRFTokenStorageService getCSRFTokenStorageService(CSRFConfigService configService)
            throws CSRFTokenStorageException;

}
