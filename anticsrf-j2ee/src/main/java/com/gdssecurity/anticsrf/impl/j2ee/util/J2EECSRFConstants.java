
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

package com.gdssecurity.anticsrf.impl.j2ee.util;

/**
 * Constants specific to J2EE applications
 */
public class J2EECSRFConstants {

    public static final String FILTER_INIT_PARAM_CSRF_CONFIG_FILE = "antiCSRFConfigFile";
    public static final String CONFIG_FILE_NAME = "anticsrf.xml";

    public static final String DEFAULT_J2EE_PROTECTION_SERVICE_NAME = "J2EE_PROTECTION_SERVICE";
    public static final String DEFAULT_SESSION_ATTRIBUTE_NAME = "SESSION_TOKEN_STORE";
    public static final String DEFAULT_COOKIE_NAME = "anticsrf";
    public static final String DEFAULT_USERSEED = "anonymous";

    public static final CharSequence CONF_VALUE_TRUE = "true";
}
