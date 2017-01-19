
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

import com.gdssecurity.anticsrf.spi.config.CSRFConfigServiceFactory;

/**
 * CSRF Configuration utility class containing accessors to the config object and config file
 */

public final class CSRFConfigUtil {

    private static CSRFConfig config;   // The config object with all loaded properties.
    private static String configFile;   // Path to the configuration file.


    private CSRFConfigUtil() {
        /* No public instantiation */
    }

    /**
     * Gets an instance of the default CSRF config service factory class.
     *
     * @return  Config service factory class used to get the config service that configures the behavior of the protection
     *          strategy.
     */
    public static CSRFConfigServiceFactory getConfigServiceFactory() {
        return DefaultCSRFConfigServiceFactory.getInstance();
    }

    /**
     * Sets the configuration object.
     *
     * @param config    configuration object to use.
     */
    public static void setConfig(CSRFConfig config) {
        CSRFConfigUtil.config = config;
    }

    /**
     *  Sets the configuration file path.
     *
     * @param configFile    path to the config file.
     */
    public static void setConfigFile(String configFile) {
        CSRFConfigUtil.configFile = configFile;
    }

    /**
     *  Gets the configuration object.
     *
     * @return  configuration object with all loaded properties.
     */
    static CSRFConfig getConfig() {
        return config;
    }

    /**
     *  Gets the path to the configuration file.
     *
     * @return  path to configuration file.
     */
    static String getConfigFile() {
        return CSRFConfigUtil.configFile;
    }

}
