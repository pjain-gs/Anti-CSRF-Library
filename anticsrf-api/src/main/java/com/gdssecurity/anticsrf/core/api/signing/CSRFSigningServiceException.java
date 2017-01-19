
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

package com.gdssecurity.anticsrf.core.api.signing;

/**
 * Exception thrown whenever a failure occurs during creation of the signing service.
 * Extends <code>Exception</code> as a base class.
 *
 */
public class CSRFSigningServiceException extends Exception {

    private static final long serialVersionUID = -5585476073223678399L;

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param msg   the detail message.
     */
    public CSRFSigningServiceException(String msg) {
        this(msg, null);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param msg   detail message.
     * @param t     the cause for the exception.
     */
    public CSRFSigningServiceException(String msg, Throwable t) {
        super(msg, t);
    }

}
