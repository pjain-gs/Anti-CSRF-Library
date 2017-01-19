
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

package com.gdssecurity.anticsrf;

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionException;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionServiceFactory;

import java.lang.reflect.Constructor;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class that creates the default CSRF protection service factory
 */
public class CSRFProtection {

    private static final Logger logger = Logger.getLogger(CSRFProtection.class.getName());

    // Name of the default protection service factory class responsible for instantiating the protection service
    private static final String DEFAULT_PROTECTION_FACTORY_CLASS =
            "com.gdssecurity.anticsrf.core.protection.DefaultCSRFProtectionServiceFactory";

    /**
     * Creates the CSRF protection service factory class from the default factory name.
     *
     * @return  {@link CSRFProtectionServiceFactory} that creates CSRF protection services.
     */
    public static CSRFProtectionServiceFactory createDefaultCSRFProtectionServiceFactory() {
        return createCSRFProtectionServiceFactory(null);
    }

    /**
     * Creates the CSRF protection service factory class from the factory name specified in configuration service, or the
     * default if one is not specified.
     *
     * @param csrfConfigService         the interface to the configuration service managing
     *                                  settings for the behavior of the protection service.
     * @return                          {@link CSRFProtectionServiceFactory} that creates CSRF protection services.
     * @throws CSRFProtectionException  if a failure occurs during the creation of the factory service class.
     */
    public static CSRFProtectionServiceFactory createCSRFProtectionServiceFactory(
            CSRFConfigService csrfConfigService)
            throws CSRFProtectionException {

        String factoryImplClassName = (csrfConfigService != null
                ? csrfConfigService.getCSRFProtectionServiceFactoryClass() : null);

        if (isBlank(factoryImplClassName)) {
            factoryImplClassName = DEFAULT_PROTECTION_FACTORY_CLASS;
        }
        return createServiceFactory(factoryImplClassName, csrfConfigService);
    }

    /**
     * Creates a CSRF protection service factory class from the specified configuration service instance and
     * factory class name.
     *
     * @param factoryImplClassName      name of the default CSRF protection service factory class.
     * @param configService             the interface to the configuration service managing
     *                                  settings for the behavior of the protection service.
     * @return                          {@link CSRFProtectionServiceFactory} that creates CSRF protection services.
     * @throws CSRFProtectionException  if a failure occurs during the creation of the factory service class.
     */
    private static final CSRFProtectionServiceFactory createServiceFactory(
            String factoryImplClassName,
            CSRFConfigService configService)
            throws CSRFProtectionException {

        if (isBlank(factoryImplClassName)) {
            throw new CSRFProtectionException("No CSRF protection service factory class provided");
        }

        Class<? extends CSRFProtectionServiceFactory> factoryClass = null;
        //  Attempt to instantiate protection service factory class.
        try {
            factoryClass = Class.forName(factoryImplClassName).asSubclass(CSRFProtectionServiceFactory.class);
        } catch (Exception ex) {
            throw new CSRFProtectionException(
                    "CSRF protection service factory class not found: " +
                            factoryImplClassName, ex);
        }

        //  Call factory class' constructor that accepts the CSRFConfigService object as an argument. If it does
        //  not exist, attempt to call the default constructor.
        try {
            //
            Constructor<? extends CSRFProtectionServiceFactory> configBasedConstructor = null;

            try {
                configBasedConstructor = (configService != null
                        ? factoryClass.getConstructor(CSRFConfigService.class)
                        : null);
            } catch (NoSuchMethodException ex) {
                logger.info(
                        "Factory does not have a config service accepting " +
                                "constructor. Will try no argument constructor. " +
                                "Class: " + factoryClass.getName());
            } catch (Exception ex) {
                logger.log(
                        Level.WARNING,
                        "Failure checking for a config service accepting " +
                                "constructor. Will try no argument constructor. " +
                                "Class: " + factoryClass.getName(), ex);
            }

            if (configBasedConstructor != null) {
                return configBasedConstructor.newInstance(configService);
            }

            Constructor<? extends CSRFProtectionServiceFactory> defaultConstructor = null;

            try {
                defaultConstructor = factoryClass.getConstructor();
            } catch (NoSuchMethodException ex) {
                throw new CSRFProtectionException(
                        "Factory class does not have a config service" +
                                " accepting constructor or a default constructor." +
                                " Class: " + factoryClass.getName(), ex);
            } catch (Exception ex) {
                throw new CSRFProtectionException(
                        "Failed while checking for a default constructor." +
                                " Class: " + factoryClass.getName(), ex);
            }

            return defaultConstructor.newInstance();
        } catch (Exception ex) {
            throw new CSRFProtectionException(
                    "Failed to create CSRF protection service factory implementation: " +
                            factoryClass.getCanonicalName(), ex);
        }
    }


    private static boolean isBlank(String str) {
        return (str == null || "".equals(str.trim()));
    }

}
