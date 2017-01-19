
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

package com.gdssecurity.anticsrf.spi.user;

/**
 * Interface for any class that implements a user context service used in facilitating processing
 * the <code>HttpServletRequest</code> for the user identity
 */
public interface CSRFUserContextService {

    /**
     * Gets the user context object used to parse the <code>HttpServletRequest</code> for user identity.
     *
     * @return {@link CSRFUserContext} used in parsing the client request for user identity.
     */
    public CSRFUserContext getUserContext();

}
