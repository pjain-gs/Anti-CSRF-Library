
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

package com.gdssecurity.anticsrf.impl.j2ee;

import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContextService;

/**
 * Request context service class used to retrieve object to parse <code>HttpServletRequest</code>
 */
public class J2EERequestContextService implements CSRFRequestContextService {

    private final String tokenParameterName;    //  Request parameter name used to pass the CSRF Token in requests.
    private final CSRFLoggingService loggingService;    //  Logging service with standard logging facilities.

    /**
     * Constructor initializing class request parameters to parse client request and logging service.
     *
     * @param tokenParameterName    request parameter name used to pass the CSRF Token in requests.
     * @param loggingService        the logging facility.
     */
    J2EERequestContextService(String tokenParameterName, CSRFLoggingService loggingService) {
        this.tokenParameterName = tokenParameterName;
        this.loggingService = loggingService;
    }

    /**
     * Gets the request context object.
     *
     * @return  Request context object.
     */
    @Override
    public CSRFRequestContext getCSRFRequestContext() {
        return new J2EECSRFRequestContext(tokenParameterName);
    }

}
