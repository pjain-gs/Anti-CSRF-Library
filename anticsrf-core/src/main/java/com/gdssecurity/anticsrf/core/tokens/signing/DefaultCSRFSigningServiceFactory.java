
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

package com.gdssecurity.anticsrf.core.tokens.signing;

import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningService;
import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningServiceException;
import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningServiceFactory;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import org.apache.commons.lang3.StringUtils;
import org.keyczar.Signer;
import org.keyczar.exceptions.KeyczarException;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Factory class for the default CSRF signing service
 */
public class DefaultCSRFSigningServiceFactory implements CSRFSigningServiceFactory {

    // A list of signing service instances mapped via key signing path names.
    private static final ConcurrentHashMap<String, CSRFSigningService> signingServices =
            new ConcurrentHashMap<String, CSRFSigningService>();

    /**
     * Gets the signing service as configured by the configuration service. Key signing file must exist for the
     * service to be created. Only one signing service will be created per configuration service object.
     *
     * @param configService                 the configuration service to manage signing service initialization.
     * @param loggingService                the logging facility.
     * @return                              {@link CSRFSigningService} that can sign and verify tokens.
     * @throws CSRFSigningServiceException  if a failure occurs during creation of the signing service.
     */
    @Override
    public CSRFSigningService getCSRFSigningService(
            CSRFConfigService configService,
            CSRFLoggingService loggingService)
            throws CSRFSigningServiceException {

        // Key signing file must exist for signing service to be created.
        String tokenSigningKeyPath = configService.getTokenSigningKeyPath();

        if (StringUtils.isBlank(tokenSigningKeyPath)) {
            throw new CSRFSigningServiceException(
                    "Obtained blank token singing key path from config service");
        }
        CSRFSigningService signingService = signingServices.get(configService.getCSRFSigningServiceFactoryClass());

        if (signingService == null) {
            createSigningService(tokenSigningKeyPath);
        }
        return signingService;
    }

    /**
     * Helper method to create the default signing service. Upon successful creation, maps the signing service
     * via the key signing file path to ensure only one instance is created per key signing file.
     *
     * @param signerKeyPath                 path to key signing file.
     * @return                              {@link CSRFSigningService} that can sign and verify tokens.
     * @throws CSRFSigningServiceException  if a failure occurred during creation of the signing service instance.
     */
    private static CSRFSigningService createSigningService(String signerKeyPath) throws CSRFSigningServiceException {
        synchronized (DefaultCSRFSigningServiceFactory.class) {
            if (!signingServices.containsKey(signerKeyPath)) {
                try {
                    Signer keyCzarSigner = new Signer(signerKeyPath);
                    DefaultCSRFSigningService signingService = new DefaultCSRFSigningService(keyCzarSigner);
                    signingServices.putIfAbsent(signerKeyPath, signingService);
                } catch (KeyczarException ex) {
                    throw new CSRFSigningServiceException(
                            "Failed to create KeyCzar signer instance using key path: " + signerKeyPath, ex);
                }
            }
        }
        return signingServices.get(signerKeyPath);
    }

}
