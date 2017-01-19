
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

import com.gdssecurity.anticsrf.core.util.CSRFFactoryException;
import com.gdssecurity.anticsrf.core.util.CSRFFactoryUtil;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigException;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigServiceFactory;
import org.apache.commons.lang3.StringUtils;

/**
 * Factory class that creates the CSRF configuration service
 */
class DefaultCSRFConfigServiceFactory implements CSRFConfigServiceFactory {

    // Only create one read-only instance of the configuration service and the factory.
    private static CSRFConfigService configServiceInstance;

    private static CSRFConfigServiceFactory configServiceFactoryInstance;


    private DefaultCSRFConfigServiceFactory() {
        /* Only private construction */
    }

    /**
     * Gets the configuration service instance.
     *
     * @return  instance of the configuration service.
     * @throws CSRFConfigException  if a failure occurs during CSRF configuration.
     */
    @Override
    public CSRFConfigService getCSRFConfigService() throws CSRFConfigException {
        if (configServiceInstance == null) {
            //initialize the service only if it doesn't exist
            initializeConfigService();
        }
        return configServiceInstance;
    }

    /**
     * Gets the config service factory class.
     *
     * @return  instance of the configuration service factory.
     */
    public static CSRFConfigServiceFactory getInstance() {
        if (configServiceFactoryInstance != null) {
            return configServiceFactoryInstance;
        }
        // synchronize access so only one factory instance can be created
        synchronized (DefaultCSRFConfigServiceFactory.class) {
            if (configServiceFactoryInstance == null) {
                configServiceFactoryInstance = new DefaultCSRFConfigServiceFactory();
            }
        }
        return configServiceFactoryInstance;
    }

    /**
     * Initializes the configuration service instance using the factory instance.
     *
     * @throws CSRFConfigException
     */
    protected static void initializeConfigService() throws CSRFConfigException {
        // synchronize access so only one config service instance is initialized
        synchronized (DefaultCSRFConfigServiceFactory.class) {
            if (configServiceInstance == null) {
                try {
                    // Check for an existing config object using the utility class.
                    // If there is no existing object, load the configuration file
                    // and obtain a config object. Create the config service instance
                    // from the service factory class config object.
                    CSRFConfig config = CSRFConfigUtil.getConfig();

                    if (config == null) {
                        config = CSRFConfigFileLoader.loadConfig(CSRFConfigUtil.getConfigFile());
                    }
                    String configServiceFactoryClassName = config.getCSRFConfigServiceFactoryClass();
                    CSRFConfigService configService = null;

                    if (StringUtils.isNotBlank(configServiceFactoryClassName)) {
                        configService = CSRFFactoryUtil.create(
                                configServiceFactoryClassName,
                                CSRFConfigService.class,
                                null);
                    }
                    configServiceInstance = (configService != null ? configService : config.createService());
                } catch (CSRFFactoryException ex) {
                    throw new CSRFConfigException("Failed to initialize CSRF configuration", ex);
                }
            }
        }
    }

}
