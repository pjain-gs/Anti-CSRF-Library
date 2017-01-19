
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

import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningException;
import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningService;
import org.keyczar.Signer;

/**
 * Default signing service class implementing <code>CSRFSigningService</code> and contains all underlying
 * services to facilitate token signing and verification
 */
public class DefaultCSRFSigningService implements CSRFSigningService {

    private Signer signer = null;


    public DefaultCSRFSigningService(Signer signer) {
        this.signer = signer;
    }


    /**
     * Signs the specified content.
     *
     * @param content                   content to sign using the signing library.
     * @return                          Cryptographically signed content.
     * @throws CSRFSigningException     if a failure occurred during signing.
     */
    @Override
    public String sign(String content) throws CSRFSigningException {
        try {
            return signer.sign(content);
        } catch (Exception ex) {
            throw new CSRFSigningException("Failed to sign content", ex);
        }
    }

    /**
     * Verifies the unsigned content against the specified signed content.
     *
     * @param content                   unsigned content to verify against the specified signed
     *                                  content using the signing library.
     * @param signedContent             signed content to verify against the specified unsigned
     *                                  content using the signing library.
     * @return                          <code>True</code> if the unsigned content and signed
     *                                      content match when both are signed
     *                                  and unsigned, <code>false</code> otherwise.
     * @throws CSRFSigningException     if a failure occurred during verification.
     */
    @Override
    public boolean verify(String content, String signedContent) throws CSRFSigningException {
        try {
            return signer.verify(content, signedContent);
        } catch (Exception ex) {
            throw new CSRFSigningException("Failed to verify signed content", ex);
        }
    }

}
