
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

package com.gdssecurity.anticsrf.impl.j2ee.tags;

import com.gdssecurity.anticsrf.impl.j2ee.J2EEProtectionServiceHolder;
import com.gdssecurity.anticsrf.spi.logging.CSRFLogger;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionService;
import org.owasp.encoder.Encode;

import javax.servlet.jsp.tagext.BodyTagSupport;
import java.io.IOException;


public class CSRFTokenParameterName extends BodyTagSupport {

    private static final long serialVersionUID = 6452788175106246620L;

    private final CSRFProtectionService protectionService =
            J2EEProtectionServiceHolder.getProtectionService();

    private final CSRFLogger csrfLogger =
            protectionService.getLoggingService().getLogger(this);

    /**
     * Writes the token request parameter name to HTML
     *
     * @return
     */
    @Override
    public int doStartTag() {
        try {
            String tokenParamName = protectionService.getConfigService().getTokenParameterName();
            pageContext.getOut().print(Encode.forHtmlAttribute(tokenParamName));

        } catch (IOException ex) {
            csrfLogger.error("Failed to encode token parameter to page", ex);
        } catch (Exception ex) {
            csrfLogger.error("Failed to write CSRF Token Parameter name taglib", ex);
        }

        return SKIP_BODY;
    }
}
