
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

/**
 * Interface for any class that implements a token storage service that stores all currently valid token
 * contexts when using session based protection
 */
public interface CSRFTokenStorageService {

    /**
     * Retrieves the token context store object in the current session using the attribute specified in
     * the configuration file.
     *
     * @return      {@link CSRFTokenContextStore} object containing all valid CSRF tokens.
     */
    CSRFTokenContextStore getTokenContextStore();

}
