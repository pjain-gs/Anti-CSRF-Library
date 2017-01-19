
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
import com.gdssecurity.anticsrf.core.tokens.StoredToken;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;

/**
 * Implements the {@link CSRFTokenContextStore} for J2EE applications to hold currently valid token
 * contexts when using session based protection.
 */
public class J2EESessionTokenContextStore implements CSRFTokenContextStore {

    private final Map<String, Object> store;    //  Store object placed in HttpSession.

    /**
     * Initializes store with existing context store.
     *
     * @param store Token context store with token objects mapping to their token values.
     */
    public J2EESessionTokenContextStore(Map<String, Object> store) {
        this.store = store;
    }

    /**
     * Returns <code>true</code> if the context store contains no elements.
     *
     * @return <code>True</code> if the context store contains no elements, <code>false</code> otherwise.
     */
    @Override
    public boolean empty() {
        return (store.isEmpty());
    }

    /**
     * Returns the value to which the specified key is paired, or <code>null</code> if there is no association for
     * this key. There can only be one value paired with each key.
     *
     * @param key   key whose paired value is to be returned.
     * @param <T>   object type of the value to be returned and to which keys are paired.
     * @return      The value to which the specified key is paired, or <code>null</code> if there is no corresponding
     *              value for this key.
     */
    @Override
    public <T> T getItem(String key) {
        return (T) (store.get(key));
    }

    /**
     * Returns the token context associated with the specified URL, or <code>null</code> if there is no association
     * for this URL. There can only be one token context associated with each URL.
     *
     * @param url   the relative path URL associated with the token context to be returned
     * @param <T>   object type of the token context to be returned.
     * @return      The token context object associated with the specified URL, or <code>null</code> if there is no
     *              token context associated with this URL.
     */
    @Override
    public <T> T getStoredToken(String url) {
        T token = null;

        for (Map.Entry<String, Object> entry : store.entrySet()) {
            //  Assume token object is of type StoredToken that have URL fields.
            StoredToken storedToken = (StoredToken) entry.getValue();
            if (storedToken != null)
                token = StringUtils.isBlank(url) ?  //  Match the input url to the storedToken's URL.
                    (StringUtils.isBlank(storedToken.getResourceURL()) ? (T) entry.getValue() : token) : // Gets site wide token.
                    (StringUtils.equals(storedToken.getResourceURL(), url) ? (T) entry.getValue() : token);//   Gets URL specific token.
        }
        return token;
    }

    /**
     * Pairs the specified item with the specified key. If there was a previous pairing with the specified key, the
     * old value is replaced with the new item.
     *
     * @param key   key with which the specified item is to be paired.
     * @param item  item to be paired with the specified key.
     */
    @Override
    public void setItem(String key, Object item) {
        store.put(key, item);
    }

    /**
     * Returns <code>true</code> if the store contains a paired value for the specified key.
     *
     * @param key   key whose presence in this store is to be tested.
     * @return      <code>True</code> if this store contains a paired value for the specified key.
     */
    @Override
    public boolean hasItem(String key) {
        return store.containsKey(key);
    }

    /**
     * Removes the pairing for a key from the store if it is present. The store wil no longer contain the specified
     * key once the call returns.
     *
     * @param key   key whose paired value is to be removed from the store.
     * @param <T>   object type of the value to be returned.
     * @return      The previous value paired with the key, or <code>null</code> if there was no pairing for this key.
     */
    @Override
    public <T> T removeItem(String key) {
        return (T) (store.remove(key));
    }

}
