
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
import org.slf4j.Logger;

/**
 * Default logger object that implements <code>CSRFLogger</code>
 */
final class DefaultCSRFLogger implements CSRFLogger {

    private final Logger logger;

    /**
     * Constructor initializing class logger.
     *
     * @param logger    logger object used for initialization.
     */
    DefaultCSRFLogger(Logger logger) {
        this.logger = logger;
    }

    /**
     * Log a message at the DEBUG level.
     *
     * @param msg   message string to be logged
     */
    @Override
    public void debug(String msg) {
        logger.debug(msg);
    }

    /**
     * Log a message regarding an exception at the DEBUG level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    @Override
    public void debug(String msg, Throwable t) {
        logger.debug(msg, t);
    }

    /**
     * Log a message at the INFO level.
     *
     * @param msg   message string to be logged
     */
    @Override
    public void info(String msg) {
        logger.info(msg);
    }

    /**
     * Log a message regarding an exception at the INFO level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    @Override
    public void info(String msg, Throwable t) {
        logger.info(msg, t);
    }

    /**
     * Log a message at the WARNING level.
     *
     * @param msg   message string to be logged
     */
    @Override
    public void warn(String msg) {
        logger.warn(msg);
    }

    /**
     * Log a message regarding an exception at the WARNING level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    @Override
    public void warn(String msg, Throwable t) {
        logger.warn(msg, t);
    }

    /**
     * Log a message at the ERROR level.
     *
     * @param msg   message string to be logged
     */
    @Override
    public void error(String msg) {
        logger.error(msg);
    }

    /**
     * Log a message regarding an exception at the ERROR level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    @Override
    public void error(String msg, Throwable t) {
        logger.error(msg, t);
    }

    /**
     * Log a message at the TRACE level.
     *
     * @param msg   message string to be logged
     */
    @Override
    public void trace(String msg) {
        logger.trace(msg);
    }

    /**
     * Log a message regarding an exception at the TRACE level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    @Override
    public void trace(String msg, Throwable t) {
        logger.trace(msg, t);
    }

}
