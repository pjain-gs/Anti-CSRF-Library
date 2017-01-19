
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

import com.gdssecurity.anticsrf.core.util.StringUtil;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * J2EE helper class to parse <code>HttpServletRequest</code> fields
 */
public class J2EEHelper {

    /**
     * Gets the relative path URL from the HTTP request with protocol, hostname, port number stripped.
     *
     * @param request   <code>HttpServletRequest</code> from which to obtain URL.
     * @return          relative path URL for HTTP request.
     */
    public static String getRequestURL(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        //  Get query string.
        String requestQueryString = StringUtil.stripNewlines(request.getQueryString());

        //  Append query string to request URI.
        String requestURL =
                StringUtil.stripNewlines(request.getRequestURI()) +
                        (StringUtils.isNotBlank(requestQueryString) ? ("?" + requestQueryString) : "");

        return requestURL;
    }


}
