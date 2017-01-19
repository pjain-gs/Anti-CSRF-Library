
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

package com.gdssecurity.anticsrf.spi.logging;

/**
 * Interface for any class that implements a logging service to facilitate system and component logging
 */
public interface CSRFLoggingService {

    /**
     * Creates a logger, if an instance does not already exist, with a set of standard logging levels using
     * the specified object.
     *
     * @param object    object associated with the logger to retrieve.
     * @return          {@link CSRFLogger} object with a set of standard logging levels.
     */
    public CSRFLogger getLogger(Object object);

    /**
     * Creates a logger, if an instance does not already exist, with a set of standard logging levels using
     * the specified class.
     *
     * @param clazz     class associated with the logger to retrieve.
     * @return          {@link CSRFLogger} object with a set of standard logging levels.
     */
    public CSRFLogger getLogger(Class<?> clazz);

    /**
     * Creates a logger, if an instance does not already exist, with a set of standard logging levels using
     * the specified name.
     *
     * @param loggerName    name of the logger to retrieve.
     * @return              {@link CSRFLogger} object with a set of standard logging levels.
     */
    public CSRFLogger getLogger(String loggerName);

}
