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

import com.gdssecurity.anticsrf.core.config.CSRFConfigServiceWrapper;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;

/**
 * Wrapper around the configuration service class for J2EE specific applications, which have state.
 */
class J2EECSRFConfigServiceWrapper extends CSRFConfigServiceWrapper {

    public J2EECSRFConfigServiceWrapper(CSRFConfigService configService) {
        super(configService);
    }

    /**
     * Gets the token storage service factory class name for J2EE.
     *
     * @return  Token storage service factory class name.
     */
    @Override
    public String getCSRFTokenStorageServiceFactoryClass() {
        return J2EESessionTokenStorageServiceFactory.class.getName();
    }

}
