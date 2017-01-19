
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

package com.gdssecurity.anticsrf.core.logging;

import com.gdssecurity.anticsrf.spi.logging.CSRFLogger;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Default logging service class implementing <code>CSRFLoggingService</code> and contains all instantiated loggers
 */
public final class DefaultCSRFLoggingService implements CSRFLoggingService {

    // Map of all instantiated loggers.
    private final ConcurrentMap<String, CSRFLogger> loggers;

    /**
     * Creates a new map to hold all instantiated loggers.
     */
    public DefaultCSRFLoggingService() {
        this.loggers = new ConcurrentHashMap<String, CSRFLogger>();
    }

    /**
     * Creates a logger, if an instance does not already exist, with a set of standard logging levels using
     * the specified object.
     *
     * @param object    object associated with the logger to retrieve.
     * @return          {@link CSRFLogger} object with a set of standard logging levels.
     */
    @Override
    public CSRFLogger getLogger(Object object) {
        return getLogger(object != null ? object.getClass() : null);
    }

    /**
     * Creates a logger, if an instance does not already exist, with a set of standard logging levels using
     * the specified class.
     *
     * @param clazz     class associated with the logger to retrieve.
     * @return          {@link CSRFLogger} object with a set of standard logging levels.
     */
    @Override
    public CSRFLogger getLogger(Class<?> clazz) {
        return getLogger(clazz != null ? clazz.getName() : "");
    }

    /**
     * Creates a logger, if an instance does not already exist, with a set of standard logging levels using
     * the specified name.
     *
     * @param loggerName    name of the logger to retrieve.
     * @return              {@link CSRFLogger} object with a set of standard logging levels.
     */
    @Override
    public CSRFLogger getLogger(String loggerName) {
        CSRFLogger logger = loggers.get(loggerName);

        if (logger != null) {
            return logger;
        }
        logger = new DefaultCSRFLogger(LoggerFactory.getLogger(loggerName));
        loggers.putIfAbsent(loggerName, logger);

        return loggers.get(loggerName);
    }

}
