
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
 * Interface for any class that implements a logging object and the standard logging levels available
 */
public interface CSRFLogger {

    /* --- DEBUG --- */

    /**
     * Log a message at the DEBUG level.
     *
     * @param msg   message string to be logged
     */
    public void debug(String msg);

    /**
     * Log a message regarding an exception at the DEBUG level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    public void debug(String msg, Throwable t);

    /* --- INFO --- */

    /**
     * Log a message at the INFO level.
     *
     * @param msg   message string to be logged
     */
    public void info(String msg);

    /**
     * Log a message regarding an exception at the INFO level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    public void info(String msg, Throwable t);

    /* --- WARN --- */

    /**
     * Log a message at the WARNING level.
     *
     * @param msg   message string to be logged
     */
    public void warn(String msg);

    /**
     * Log a message regarding an exception at the WARNING level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    public void warn(String msg, Throwable t);

    /* --- ERROR --- */

    /**
     * Log a message at the ERROR level.
     *
     * @param msg   message string to be logged
     */
    public void error(String msg);

    /**
     * Log a message regarding an exception at the ERROR level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    public void error(String msg, Throwable t);

    /* --- TRACE --- */

    /**
     * Log a message at the TRACE level.
     *
     * @param msg   message string to be logged
     */
    public void trace(String msg);

    /**
     * Log a message regarding an exception at the TRACE level.
     *
     * @param msg   message string about the exception to be logged
     * @param t     the exception to log
     */
    public void trace(String msg, Throwable t);


}
