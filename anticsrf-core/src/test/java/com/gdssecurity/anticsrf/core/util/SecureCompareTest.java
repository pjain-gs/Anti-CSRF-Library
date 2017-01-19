
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

import org.junit.Assert;
import org.junit.Test;

public class SecureCompareTest {

    @Test
    public void test_isEqualMatch() {
        String random = "hello world";
        Assert.assertTrue(SecureCompare.isEqual(random.getBytes(), random.getBytes()));
    }

    @Test
    public void test_isEqualMismatch() {
        String random = "hello world";
        String randomTwo = "Hello world";
        Assert.assertFalse(SecureCompare.isEqual(random.getBytes(), randomTwo.getBytes()));
    }

    @Test
    public void test_isEqualMismatch2() {
        String random = "hello world";
        String randomTwo = "helloworld";
        Assert.assertFalse(SecureCompare.isEqual(random.getBytes(), randomTwo.getBytes()));
    }

    @Test
    public void test_isEqualMismatch3() {
        String random = "hello world";
        String randomTwo = "hello/world";
        Assert.assertFalse(SecureCompare.isEqual(random.getBytes(), randomTwo.getBytes()));
    }

    @Test
    public void test_isEqualMismatch4() {
        String random = "hello world";
        String randomTwo = "hello+world";
        Assert.assertFalse(SecureCompare.isEqual(random.getBytes(), randomTwo.getBytes()));
    }
}