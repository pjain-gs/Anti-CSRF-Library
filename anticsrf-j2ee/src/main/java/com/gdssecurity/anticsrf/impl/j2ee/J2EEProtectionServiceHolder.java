
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
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionService;

/**
 * Accessors for the CSRF protection service used by J2EE applications.
 */
public final class J2EEProtectionServiceHolder {

    private static CSRFProtectionService protectionService;

    /**
     * The protection service which is created for each session is assigned to CSRFProtectionService.
     *
     * @param service   Protection service to use.
     */
    static void setService(CSRFProtectionService service) {
        protectionService = service;
    }

    /**
     * Return the instance of the protection service.
     *
     * @return  Protection service instance.
     */
    public static CSRFProtectionService getProtectionService() {
        return protectionService;
    }

}
