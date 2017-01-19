
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

package com.gdssecurity.anticsrf.core.util;

import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;

/**
 * Factory utility class used to create instances of factory classes.
 */
public final class CSRFFactoryUtil {

    private static final Logger logger = LoggerFactory.getLogger(CSRFFactoryUtil.class);

    /**
     * Creates an instance of the specified factory class.
     *
     * @param factoryImplClassName  factory implementation class name.
     * @param factoryInterface      factory interface class.
     * @param defaultFactory        default factory class.
     * @param <S>                   factory interface class type.
     * @param <T>                   default factory class type.
     * @return                      Instance of factory class.
     * @throws CSRFFactoryException if factory class could not instantiated.
     */
    public static final <S, T extends S> S create(
            String factoryImplClassName,
            Class<S> factoryInterface,
            Class<T> defaultFactory)
            throws CSRFFactoryException {

        return create(factoryImplClassName, factoryInterface, defaultFactory, null);
    }

    /**
     * Creates a CSRF factory class from the specified configuration service instance and
     * factory class name.
     *
     * @param factoryImplClassName  name of the default CSRF protection service factory class.
     * @param factoryInterface      factory interface class.
     * @param defaultFactory        default factory class.
     * @param configService         the configuration service for managing service initialization.
     * @param <S>                   factory class type.
     * @return                      Instance of factory class.
     * @throws CSRFFactoryException
     */
    public static final <S> S create(
            String factoryImplClassName,
            Class<S> factoryInterface,
            Class<? extends S> defaultFactory,
            CSRFConfigService configService)
            throws CSRFFactoryException {

        Class<? extends S> factoryClass = null;

        //  If given the factory implementation class name, attempt to instantiate it.
        if (StringUtils.isNotBlank(factoryImplClassName)) {
            try {
                factoryClass = Class
                        .forName(factoryImplClassName)
                        .asSubclass(factoryInterface);
            } catch (Exception ex) {
                throw new CSRFFactoryException(
                        "Failed to instantiate factory class: " + factoryImplClassName, ex);
            }
        } else if (defaultFactory != null) {
            factoryClass = defaultFactory;
        }

        //  Call factory class' constructor that accepts the CSRFConfigService object as an argument. If it does
        //  not exist, attempt to call the default constructor.
        if (factoryClass != null) {
            try {
                Constructor<? extends S> configBasedConstructor = null;

                try {
                    configBasedConstructor = (configService != null
                            ? factoryClass.getConstructor(CSRFConfigService.class)
                            : null);
                } catch (NoSuchMethodException ex) {
                    logger.info(
                            "Factory does not have a config service accepting" +
                                    " constructor. Will try no argument constructor." +
                                    " Class: " + factoryClass.getName());
                } catch (Exception ex) {
                    logger.warn(
                            "Failed while checking for a config service accepting" +
                                    " constructor. Will try no argument constructor." +
                                    " Class: " + factoryClass.getName(), ex);
                }

                if (configBasedConstructor != null) {
                    return configBasedConstructor.newInstance(configService);
                }

                Constructor<? extends S> defaultConstructor = null;

                try {
                    defaultConstructor = factoryClass.getConstructor();
                } catch (NoSuchMethodException ex) {
                    logger.info(
                            "Factory class does not have a config service" +
                                    " accepting constructor or a default constructor." +
                                    " Class: " + factoryClass.getName());
                } catch (Exception ex) {
                    logger.warn(
                            "Failed while checking for a default constructor." +
                                    " Class: " + factoryClass.getName(), ex);
                }

                if (defaultConstructor != null) {
                    return defaultConstructor.newInstance();
                }
            } catch (Exception ex) {
                throw new CSRFFactoryException(
                        "Failed to create instance: " + factoryClass.getName(), ex);
            }
        }

        return null;
    }

}
