
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * J2EE wrapper for the <code>HttpServletRequest</code>. Handles every request in a new thread
 */
public class J2EEServletContext {

    /**
     * Creates a thread local variable for the <code>HttpServletRequest</code>.
     */
    private static ThreadLocal<HttpServletRequest> threadLocalHttpRequest =
            new ThreadLocal<HttpServletRequest>();

    /**
     * Sets the thread local variable to the specified request.
     *
     * @param request   <code>HttpServletRequest</code> object used to set thread local variable.
     */
    static void bindContext(HttpServletRequest request) {
        threadLocalHttpRequest.set(request);
    }

    /**
     * Removes the thread local variable's value.
     */
    static void unbindContext() {
        threadLocalHttpRequest.remove();
    }

    /**
     * Returns the value of the thread local variable.
     *
     * @return  <code>HttpServletRequest</code> copy stored in the thread local variable.
     */
    static HttpServletRequest getRequest() {
        return threadLocalHttpRequest.get();
    }

    /**
     * Gets the session object in the <code>HttpServletRequest</code>. Create the <code>HttpSession</code> if it
     * does not exist. Returns <code>null</code> the the request does not exist.
     *
     * @return  <code>HttpSession</code> object. Returns <code>null</code> the the request does not exist.
     */
    static HttpSession getSession() {
        HttpServletRequest request = getRequest();
        return (request != null ? request.getSession(true) : null);
    }

}
