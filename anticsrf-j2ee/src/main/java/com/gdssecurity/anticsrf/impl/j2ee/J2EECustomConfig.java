
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

/**
 * Configuration specific to J2EE applications using Anti-CSRF.
 */
public enum J2EECustomConfig {

    PROTECTION_SERVICE_NAME("serviceName"),
    MONITOR_MODE("monitorMode"),
    AJAX_ERROR("ajax"),
    ERROR_HANDLING_ACTION("error"),
    ERROR_HANDLING_VALUE("errorval");

    private final String configKey;

    private J2EECustomConfig(String configKey) {
        this.configKey = configKey;
    }

    public String configKey() {
        return configKey;
    }
}