
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

package com.gdssecurity.anticsrf.spi.rules;

/**
 * Interface for the resource protection rule object created for every URL and containing its protection properties.
 */
public interface CSRFResourceProtectionRule {

    /**
     * Returns the URL associated with this object upon creation.
     *
     * @return Resource URL for this given protection rule specified at creation.
     */
    public String getResourceURL();

    /**
     * Returns the token timeout associated with this object upon creation.
     *
     * @return Timeout value for this given protection rule.
     */
    public Long getTokenTimeout();

}
