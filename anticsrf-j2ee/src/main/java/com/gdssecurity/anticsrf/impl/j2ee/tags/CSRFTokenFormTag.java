
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
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionException;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionService;
import org.apache.commons.lang3.StringUtils;
import org.owasp.encoder.Encode;

import javax.servlet.jsp.tagext.BodyTagSupport;
import java.io.IOException;


public class CSRFTokenFormTag extends BodyTagSupport {

    private static final long serialVersionUID = 3435643224980402138L;

    private final CSRFProtectionService protectionService =
            J2EEProtectionServiceHolder.getProtectionService();

    private final CSRFLogger csrfLogger =
            protectionService.getLoggingService().getLogger(this);


    /**
     * Adds CSRF Token to POST form as hidden variable
     *
     * @return int
     */
    @Override
    public int doStartTag() {
        try {
            String tokenParamName = protectionService.getConfigService().getTokenParameterName();

            String csrfToken = protectionService.getToken();  //protectionService.generateResourceToken(requestURL, null);
            if (StringUtils.isBlank(csrfToken))
                csrfToken = protectionService.generateToken();
            pageContext.getRequest().setAttribute(
                    protectionService.getConfigService().getRequestAttributeName(), csrfToken);

            pageContext.getOut().print(
                    "<input" +
                            " type='hidden'" +
                            " name='" + Encode.forHtmlAttribute(tokenParamName) + "'" +
                            " value='" + Encode.forHtmlAttribute(csrfToken) + "' >" +
                            "</input>");

        } catch (CSRFProtectionException ex) {
            csrfLogger.error("Failed to obtain CSRF token", ex);
        } catch (IOException ex) {
            csrfLogger.error("Failed to encode CSRF token to page", ex);
        } catch (Exception ex) {
            csrfLogger.error("Failed to write CSRF Token through taglib", ex);
        }

        return SKIP_BODY;
    }
}
