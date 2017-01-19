
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

package com.gdssecurity.anticsrf.core.rules;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Rules cache that storing already checked URLs and their associated protection properties or exemption properties.
 */
public class RulesCache<T> {

    private static final int DEFAULT_CAPACITY = 1000;

    private Map<String, T> store;


    RulesCache() {
        this(DEFAULT_CAPACITY);
    }

    /**
     * Initializes cache with specified capacity.
     *
     * @param capacity  capacity of cache. Uses default value if specified capacity is not a positive numeric value.
     */
    RulesCache(Integer capacity) {
        // Not synchronized for performance
        this.store = new Store<T>(capacity > 0 ? capacity : DEFAULT_CAPACITY);
    }

    /**
     * Get rule cached via specified key, or <code>null</code> if it does not exist.
     *
     * @param requestRuleKey    key for which to find cached rule.
     * @return                  Rule cached to specified key, or <code>null</code> if it does not exist.
     */
    public T get(String requestRuleKey) {
        return store.get(requestRuleKey);
    }

    /**
     * Caches specified rule with specified key. If the cache previously contained a rule for
     * the key, the old rule is replaced by the specified rule.
     *
     * @param requestRuleKey    key with which to cache rule.
     * @param rule              rule to cache with key.
     */
    public void put(String requestRuleKey, T rule) {
        store.put(requestRuleKey, rule);
    }
    
    
    /*
     * ===========
     * STORE CLASS
     * ===========
     */

    private static final class Store<T> extends LinkedHashMap<String, T> {

        private static final long serialVersionUID = 2763024183140589187L;

        private int cacheCapacity = -1;

        /**
         * Initializes linked hash map object to use for cache with specified capacity, load factory of 0.75, and
         * access order mode.
         * @param capacity  initial capacity.
         */
        public Store(int capacity) {
            super((capacity + 1), 0.75F, true);
            this.cacheCapacity = capacity;
        }

        /**
         * Returns <code>true</code> if the eldest entry should be removed from the cache. Allows
         * cache to reduce memory consumption by deleting stale entries.
         * @param eldest    the least recently accessed entry in cache.
         * @return          <code>True</code> if the eldest entry should be removed from the cache,
         *                  <code>false</code> if it should be retained.
         */
        @Override
        public boolean removeEldestEntry(Map.Entry<String, T> eldest) {
            return (cacheCapacity > 0 && size() > cacheCapacity);
        }

    }

}
