
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

package com.gdssecurity.anticsrf.core.config;

import com.gdssecurity.anticsrf.core.util.Constants;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigException;

import java.util.Properties;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class used while loading CSRF configuration file
 */
public final class CSRFConfigFileLoaderUtil {

    private CSRFConfigFileLoaderUtil() {
        /* No public instantiation */
    }

    /**
     * Returns <code>true</code> if the specified timeout value is greater than zero, <code>false</code> otherwise.
     *
     * @param timeout   timeout value to validate.
     * @param LOG       optional logger object to log parsing exception.
     * @return          <code>True</code> if supplied timeout is valid, <code>false</code> otherwise.
     */
    static boolean validateTimeout(final String timeout, Logger LOG) {
        try {
            return (Long.parseLong(timeout) > 0);
        } catch (NumberFormatException ex) {
            if (LOG != null)
                LOG.severe("Invalid timeout value submitted. Value should be a positive numeric value. EnteredValue=" + timeout);
        }
        return false;
    }

    /**
     * Validates the supplied URL to ensure it's a relative path and does not contain invalid characters.
     *
     * @param url                   URL to validate.
     * @return                      Relative path URL with valid characters.
     * @throws CSRFConfigException  if invalid characters were passed in the URL.
     */
    static String getValidatedUrl(String url) throws CSRFConfigException {
        url = url.replaceAll("\\s", ""); // Strip out the whitespaces.

        if (!url.startsWith("/")) {
            throw new CSRFConfigException("Invalid URL is not in a valid format."
                    + "We are expecting a relative path and should therefore begin with a '/'. EnteredUrl=" + url);
        }
        Pattern pattern = Pattern.compile("^[A-Za-z1-9_.~:/#@=;,'\\-\\?\\[\\]\\+\\*\\{\\}\\&\\$\\|]+$");
        Matcher matcher = pattern.matcher(url);

        if (!matcher.matches()) {
            throw new CSRFConfigException("Invalid character passed in the URL. EnteredUrl=" + url);
        }

        return url;
    }

    /**
     * Returns <code>true</code> if the protection mode in the configuration file is set to HMAC.
     *
     * @param csrfConfig    configuration object to check for protection mode.
     * @return              <code>True</code> if the protection mode is HMAC.
     */
    static boolean isHmacMode(final Properties csrfConfig) {
        return csrfConfig.getProperty(Constants.CONF_MODE).equals(Constants.MODES.hmac.toString());
    }

    /**
     * Returns <code>true</code> if the protection mode in the configuration file is set to session.
     *
     * @param csrfConfig    configuration object to check for protection mode.
     * @return              <code>True</code> if the protection mode is session.
     */
    static boolean isSessionMode(final Properties csrfConfig) {
        return csrfConfig.getProperty(Constants.CONF_MODE).equals(Constants.MODES.session.toString());
    }
}
