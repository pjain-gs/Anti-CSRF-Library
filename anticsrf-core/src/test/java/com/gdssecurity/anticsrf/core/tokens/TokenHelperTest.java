
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

package com.gdssecurity.anticsrf.core.tokens;

import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;

public class TokenHelperTest {

    private static final String TOKEN_FIELD_DELIMITER = ":";
    private final static String userSeed = "USERSEED";
    private final static String uri = "URI";
    private final static Long tokenTimeout = 3000L;
    private final static String tokenTimeoutString = String.valueOf(3000L);

    @Test
    public void test_generatePlainTokenStringNoUserSeedNoUrlNoTimeout() {
        Assert.assertTrue(StringUtils.isBlank(TokenHelper.generatePlainTokenString(null, null, null)));
    }

    @Test
    public void test_generatePlainTokenStringNoUrlNoTimeout() {
        Assert.assertTrue(StringUtils.equals(TokenHelper.generatePlainTokenString(null, userSeed, null),
                userSeed + TOKEN_FIELD_DELIMITER));
    }

    @Test
    public void test_generatePlainTokenStringNoUserSeedNoTimeout() {
        Assert.assertTrue(StringUtils.equals(TokenHelper.generatePlainTokenString(uri, null, null),
                uri + TOKEN_FIELD_DELIMITER));
    }

    @Test
    public void test_generatePlainTokenStringNoUserSeedNoUrl() {
        Assert.assertTrue(StringUtils.equals(TokenHelper.generatePlainTokenString(null, null, tokenTimeout),
                tokenTimeoutString));
    }

    @Test
    public void test_generatePlainTokenStringNoTimeout() {
        Assert.assertTrue(StringUtils.equals(TokenHelper.generatePlainTokenString(uri, userSeed, null),
                userSeed + TOKEN_FIELD_DELIMITER + uri + TOKEN_FIELD_DELIMITER));
    }

    @Test
    public void test_generatePlainTokenStringNoUserSeed() {
        Assert.assertTrue(StringUtils.equals(TokenHelper.generatePlainTokenString(uri, null, tokenTimeout),
                uri + TOKEN_FIELD_DELIMITER + tokenTimeoutString));
    }

    @Test
    public void test_generatePlainTokenStringNoUrl() {
        Assert.assertTrue(StringUtils.equals(TokenHelper.generatePlainTokenString(null, userSeed, tokenTimeout),
                userSeed + TOKEN_FIELD_DELIMITER + tokenTimeoutString));
    }

    @Test
    public void test_generatePlainTokenStringMatch() {
        Assert.assertTrue(StringUtils.equals(TokenHelper.generatePlainTokenString(uri, userSeed, tokenTimeout),
                userSeed + TOKEN_FIELD_DELIMITER + uri + TOKEN_FIELD_DELIMITER + tokenTimeoutString));
    }

    @Test
    public void test_timestampIsExpiredTrue() {
        Long creationTime = new Date().getTime();
        Assert.assertTrue(TokenHelper.timestampIsExpired(creationTime, 0L));
    }

    @Test
    public void test_timestampIsExpiredFalse() {
        Long creationTime = new Date().getTime();
        Assert.assertFalse(TokenHelper.timestampIsExpired(creationTime, 10000L));
    }

}