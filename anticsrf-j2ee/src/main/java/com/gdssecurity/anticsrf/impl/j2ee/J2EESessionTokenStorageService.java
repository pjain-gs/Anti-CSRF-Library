
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

import com.gdssecurity.anticsrf.core.api.store.CSRFTokenContextStore;
import com.gdssecurity.anticsrf.core.api.store.CSRFTokenStorageService;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 * Implements {@link CSRFTokenStorageService} to facilitate session token storage in J2EE
 */
public class J2EESessionTokenStorageService implements CSRFTokenStorageService {

    private final String sessionStoreKey;   //  HttpSession attribute with which to store the token context store.

    /**
     * Initializes the J2EE token storage service with the specified session attribute key. Key is used to find
     * the token context store within the <code>HttpSession</code> object.
     *
     * @param sessionAttribute  session attribute used to store token context store object within <code>HttpSession</code>
     *                          object.
     */
    public J2EESessionTokenStorageService(String sessionAttribute) {
        this.sessionStoreKey = sessionAttribute;
    }

    /**
     * Retrieves the token context store object in the current session using the attribute specified in
     * the configuration file.
     *
     * @return      {@link CSRFTokenContextStore} object containing all valid CSRF tokens.
     */
    @Override
    public CSRFTokenContextStore getTokenContextStore() {
        return new J2EESessionTokenContextStore(getStore());
    }


    /**
     * Gets the token context storage object from the request's session attribute, or creates one if it does not exist.
     *
     * @return  Token context store.
     */
    protected Map<String, Object> getStore() {
        HttpSession session = J2EEServletContext.getSession();

        if (session == null) {
            throw new J2EESessionStoreException(
                    "Failed to get an underlying HTTP session for token store retrieval.");
        }
        Map<String, Object> store = (Map<String, Object>) (session.getAttribute(sessionStoreKey));

        if (store != null) {
            return store;
        }
        synchronized (this) {
            store = new HashMap<String, Object>();
            session.setAttribute(sessionStoreKey, store);
        }
        return store;
    }

}
