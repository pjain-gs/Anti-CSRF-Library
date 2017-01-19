
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

package com.gdssecurity.anticsrf.spi.request;

/**
 * Interface for the request context object used in processing the <code>HttpServletRequest</code>
 */
public interface CSRFRequestContext {

    /**
     * Gets the URL from the <code>HttpServletRequest</code>.
     *
     * @return  Relative path URL and query string obtained from processing the <code>HttpServletRequest</code>.
     */
    public String getRequestURL();

    /**
     *  Gets the CSRF token contained in the <code>HttpServletRequest</code>.
     *
     * @return  CSRF token obtained from processing the <code>HttpServletRequest</code> as determined
     * by the protection strategy.
     */
    public String getRequestToken();

}
