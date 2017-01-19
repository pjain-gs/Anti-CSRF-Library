
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

import com.gdssecurity.anticsrf.core.api.store.CSRFTokenContextStore;
import com.gdssecurity.anticsrf.core.api.store.CSRFTokenStorageService;
import com.gdssecurity.anticsrf.core.rules.PatternProtectionRule;
import com.gdssecurity.anticsrf.core.util.SecureCompare;
import com.gdssecurity.anticsrf.spi.logging.CSRFLogger;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.tokens.*;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.xml.bind.DatatypeConverter;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.regex.Pattern;

import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({StoreBasedCSRFTokenService.class, CSRFTokenStorageService.class, CSRFLoggingService.class, CSRFTokenGenerationContext.class
        , SecureRandom.class, DatatypeConverter.class, byte[].class, TokenVerificationContext.class, CSRFRequestContext.class, PatternProtectionRule.class
        , CSRFTokenContextStore.class, CSRFUserContext.class, StoredToken.class, SecureCompare.class})
public class StoreBasedCSRFTokenServiceTest {

    private final static String token = "BASE64TOKEN0123456789+/=abcdefghijklmnopqrst";

    private final static String uri = "URI";
    private final static String userIdentifier = "USERIDENTIFIER";
    private final static Pattern tokenPattern = Pattern.compile("^[a-zA-Z0-9+=/]{32}");

    private static CSRFTokenContextStore contextStore;
    private static CSRFTokenStorageService tokenStorageService;
    private static CSRFLoggingService loggingService;
    private static CSRFTokenGenerationContext tokenGenerationContext;
    private static TokenVerificationContext tokenVerificationContext;
    private static CSRFRequestContext requestContext;
    private static PatternProtectionRule patternProtectionRule;
    private static CSRFLogger logger;
    private static StoreBasedCSRFTokenService storeBasedCSRFTokenService;

    @BeforeClass
    public static void setup() throws Exception {
        tokenStorageService = Mockito.mock(CSRFTokenStorageService.class);
        loggingService = Mockito.mock(CSRFLoggingService.class);
        logger = Mockito.mock(CSRFLogger.class);
        tokenGenerationContext = Mockito.mock(CSRFTokenGenerationContext.class);
        tokenVerificationContext = Mockito.mock(TokenVerificationContext.class);
        requestContext = Mockito.mock(CSRFRequestContext.class);
        patternProtectionRule = Mockito.mock(PatternProtectionRule.class);
        when(tokenGenerationContext.getResourceURL()).thenReturn(uri);
        when(tokenGenerationContext.getUserContext()).thenReturn(null);
        when(tokenGenerationContext.getResourceProtectionRule()).thenReturn(null);

    }

    @Before
    public void before() {
        contextStore = Mockito.mock(CSRFTokenContextStore.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(loggingService.getLogger(StoreBasedCSRFTokenService.class)).thenReturn(logger);
        doNothing().when(logger).warn(Mockito.anyString());
        doNothing().when(logger).debug(Mockito.anyString());
        storeBasedCSRFTokenService = new StoreBasedCSRFTokenService(tokenStorageService, loggingService);
    }

    @Test(expected = CSRFTokenGenerationException.class)
    public void test_generateTokenSunSecureRandomExceptionThrowsNoSuchAlgorithm() throws NoSuchAlgorithmException, NoSuchProviderException, CSRFTokenGenerationException {
        PowerMockito.mockStatic(SecureRandom.class);
        PowerMockito.when(SecureRandom.getInstance(Mockito.eq("SHA1PRNG"), Mockito.eq("SUN"))).thenThrow(new NoSuchAlgorithmException(""));
        storeBasedCSRFTokenService.generateToken(null);
    }

    @Test(expected = CSRFTokenGenerationException.class)
    public void test_generateTokenThrowsNoSuchProviderException() throws NoSuchAlgorithmException, NoSuchProviderException, CSRFTokenGenerationException {
        PowerMockito.mockStatic(SecureRandom.class);
        PowerMockito.when(SecureRandom.getInstance(Mockito.eq("SHA1PRNG"), Mockito.eq("SUN"))).thenThrow(new NoSuchProviderException(""));
        PowerMockito.when(SecureRandom.getInstance(Mockito.eq("SHA1PRNG"))).thenThrow(new NoSuchAlgorithmException(""));
        storeBasedCSRFTokenService.generateToken(null);
    }

    @Test(expected = CSRFTokenGenerationException.class)
    public void test_generateTokenThrowsExceptionNoPreferredProvider() throws NoSuchAlgorithmException, NoSuchProviderException, CSRFTokenGenerationException {
        PowerMockito.mockStatic(SecureRandom.class);
        PowerMockito.when(SecureRandom.getInstance(Mockito.eq("SHA1PRNG"), Mockito.eq("SUN"))).thenThrow(new NoSuchProviderException(""));
        PowerMockito.when(SecureRandom.getInstance(Mockito.eq("SHA1PRNG"))).thenReturn(null);
        storeBasedCSRFTokenService.generateToken(null);
    }



    @Test
    public void test_generateTokenNullContext() throws NoSuchAlgorithmException, NoSuchProviderException, CSRFTokenGenerationException {
        PowerMockito.mockStatic(DatatypeConverter.class);
        PowerMockito.when(DatatypeConverter.printBase64Binary(Mockito.any(byte[].class))).thenReturn(token);
        Assert.assertTrue(StringUtils.equals(token, storeBasedCSRFTokenService.generateToken(null)));
    }

    @Test
    public void test_generateTokenWithContext() throws NoSuchAlgorithmException, NoSuchProviderException, CSRFTokenGenerationException {
        PowerMockito.mockStatic(DatatypeConverter.class);
        PowerMockito.when(DatatypeConverter.printBase64Binary(Mockito.any(byte[].class))).thenReturn(token);
        Assert.assertTrue(StringUtils.equals(token, storeBasedCSRFTokenService.generateToken(tokenGenerationContext)));
    }

    @Test
    public void test_generateTokenNullContextNoDuplicate() throws NoSuchAlgorithmException, NoSuchProviderException, CSRFTokenGenerationException {
        String uniqueToken = storeBasedCSRFTokenService.generateToken(null);
        String uniqueToken2 = storeBasedCSRFTokenService.generateToken(null);
        Assert.assertNotEquals(uniqueToken, uniqueToken2);
        Assert.assertTrue(tokenPattern.matcher(uniqueToken).find());
        Assert.assertTrue(tokenPattern.matcher(uniqueToken2).find());
    }

    @Test
    public void test_generateTokenWithContextNoDuplicate() throws NoSuchAlgorithmException, NoSuchProviderException, CSRFTokenGenerationException {
        StoreBasedCSRFTokenService spy = Mockito.spy(storeBasedCSRFTokenService);
        doReturn(null)
                .when(spy)
                .getToken(Mockito.eq(uri));
        String uniqueToken = storeBasedCSRFTokenService.generateToken(tokenGenerationContext);
        String uniqueToken2 = storeBasedCSRFTokenService.generateToken(tokenGenerationContext);
        Assert.assertNotEquals(uniqueToken, uniqueToken2);
        Assert.assertTrue(tokenPattern.matcher(uniqueToken).find());
        Assert.assertTrue(tokenPattern.matcher(uniqueToken2).find());
    }

    @Test
    public void test_generateTokenWithContextFindExisting() throws NoSuchAlgorithmException, NoSuchProviderException, CSRFTokenGenerationException {
        PowerMockito.mockStatic(DatatypeConverter.class);
        PowerMockito.when(DatatypeConverter.printBase64Binary(Mockito.any(byte[].class))).thenReturn("OTHERTOKEN");
        StoreBasedCSRFTokenService spy = Mockito.spy(storeBasedCSRFTokenService);
        doReturn(token)
                .when(spy)
                .getToken(Mockito.eq(uri));
        Assert.assertTrue(StringUtils.equals(token, spy.generateToken(tokenGenerationContext)));
    }


    @Test
    public void test_getTokenNullTokenForNullUrl() throws CSRFTokenGenerationException {
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getStoredToken((String) Mockito.isNull())).thenReturn(mockToken);
        when(mockToken.getTokenValue()).thenReturn(null);
        Assert.assertNull(storeBasedCSRFTokenService.getToken(null));
    }

    @Test
    public void test_getTokenNullTokenForNullAndBlankUrl() throws CSRFTokenGenerationException {
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getStoredToken((String) Mockito.isNull())).thenReturn(mockToken);
        when(mockToken.getTokenValue()).thenReturn(null);
        when(contextStore.getStoredToken(Mockito.eq(""))).thenReturn(mockToken);
        when(mockToken.getTokenValue()).thenReturn(null);
        Assert.assertEquals(storeBasedCSRFTokenService.getToken(null), storeBasedCSRFTokenService.getToken(""));
    }

    @Test
    public void test_getTokenNullUrl() throws CSRFTokenGenerationException {
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getStoredToken((String) Mockito.isNull())).thenReturn(mockToken);
        when(mockToken.getTokenValue()).thenReturn(token);
        Assert.assertEquals(token, storeBasedCSRFTokenService.getToken(null));
    }

    @Test
    public void test_getTokenForNullAndBlankUrl() throws CSRFTokenGenerationException {
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getStoredToken((String) Mockito.isNull())).thenReturn(mockToken);
        when(mockToken.getTokenValue()).thenReturn(token);
        when(contextStore.getStoredToken(Mockito.eq(""))).thenReturn(mockToken);
        when(mockToken.getTokenValue()).thenReturn(token);
        Assert.assertEquals(storeBasedCSRFTokenService.getToken(null), storeBasedCSRFTokenService.getToken(""));
    }

    @Test
    public void test_getTokenNullTokenForUrl() throws CSRFTokenGenerationException {
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getStoredToken(Mockito.eq(uri))).thenReturn(mockToken);
        when(mockToken.getTokenValue()).thenReturn(null);
        Assert.assertNull(storeBasedCSRFTokenService.getToken(uri));
    }

    @Test
    public void test_getTokenForUrl() throws CSRFTokenGenerationException {
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getStoredToken(Mockito.eq(uri))).thenReturn(mockToken);
        when(mockToken.getTokenValue()).thenReturn(token);
        Assert.assertEquals(token, storeBasedCSRFTokenService.getToken(uri));
    }

    @Test
    public void test_verifyTokenExemptUrlVerificationPass() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(null);
        Assert.assertTrue(storeBasedCSRFTokenService.verifyToken(null, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenBlankTokenVerificationFail() throws CSRFTokenVerificationException {
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(null, null));
    }

    @Test
    public void test_verifyTokenNoStoredTokenVerificationFail() throws CSRFTokenVerificationException {
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(null);
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, null));
    }

    @Test
    public void test_verifyTokenRequestTokenMisMatchVerificationFail() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(tokenVerificationContext.getUserContext()).thenReturn(null);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn("BADTOKENBASE64TOKEN0123456789+/=abcdefghijk");
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.isOneTimeUseToken()).thenReturn(false);
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenRequestUserMisMatchVerificationFail() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        CSRFUserContext csrfUserContext = Mockito.mock(CSRFUserContext.class);
        when(tokenVerificationContext.getUserContext()).thenReturn(csrfUserContext);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn(token);
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.isOneTimeUseToken()).thenReturn(false);
        when(mockToken.getUserIdentifier()).thenReturn(userIdentifier);
        when(csrfUserContext.getUserIdentifier()).thenReturn("BADUSERIDENTIFIER");
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenRequestUserNullVerificationFail() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        CSRFUserContext csrfUserContext = Mockito.mock(CSRFUserContext.class);
        when(tokenVerificationContext.getUserContext()).thenReturn(csrfUserContext);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn(token);
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.isOneTimeUseToken()).thenReturn(false);
        when(mockToken.getUserIdentifier()).thenReturn(userIdentifier);
        when(csrfUserContext.getUserIdentifier()).thenReturn(null);
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenSecureCompareMisMatchVerificationFail() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        CSRFUserContext csrfUserContext = Mockito.mock(CSRFUserContext.class);
        when(tokenVerificationContext.getUserContext()).thenReturn(csrfUserContext);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn(token);
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.isOneTimeUseToken()).thenReturn(false);
        when(mockToken.getUserIdentifier()).thenReturn(userIdentifier);
        when(csrfUserContext.getUserIdentifier()).thenReturn(userIdentifier);
        when(mockToken.getTokenValue()).thenReturn("BADTOKENBASE64TOKEN0123456789+/=abcdefghijk");
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenTimestampExpiredVerificationFail() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        CSRFUserContext csrfUserContext = Mockito.mock(CSRFUserContext.class);
        when(tokenVerificationContext.getUserContext()).thenReturn(csrfUserContext);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn(token);
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.isOneTimeUseToken()).thenReturn(false);
        when(mockToken.getUserIdentifier()).thenReturn(userIdentifier);
        when(csrfUserContext.getUserIdentifier()).thenReturn(userIdentifier);
        when(mockToken.getTokenValue()).thenReturn(token);
        when(mockToken.getTokenTimeout()).thenReturn(0L);
        when(mockToken.getTokenTimestamp()).thenReturn(new Date().getTime());
        PowerMockito.mockStatic(SecureCompare.class);
        PowerMockito.when(SecureCompare.isEqual(Mockito.any(byte[].class), Mockito.any(byte[].class))).thenReturn(true);
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenRequestTokenUrlMisMatchVerificationFail() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        CSRFUserContext csrfUserContext = Mockito.mock(CSRFUserContext.class);
        when(tokenVerificationContext.getUserContext()).thenReturn(csrfUserContext);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn(token);
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.isOneTimeUseToken()).thenReturn(false);
        when(mockToken.getUserIdentifier()).thenReturn(userIdentifier);
        when(csrfUserContext.getUserIdentifier()).thenReturn(userIdentifier);
        when(mockToken.getTokenValue()).thenReturn(token);
        when(mockToken.getTokenTimeout()).thenReturn(10000L);
        when(mockToken.getTokenTimestamp()).thenReturn(new Date().getTime());
        when(mockToken.getResourceURL()).thenReturn(uri);
        when(requestContext.getRequestURL()).thenReturn("BADURL");
        PowerMockito.mockStatic(SecureCompare.class);
        PowerMockito.when(SecureCompare.isEqual(Mockito.any(byte[].class), Mockito.any(byte[].class))).thenReturn(true);
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenRequestTokenUrlNullVerificationFail() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        CSRFUserContext csrfUserContext = Mockito.mock(CSRFUserContext.class);
        when(tokenVerificationContext.getUserContext()).thenReturn(csrfUserContext);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn(token);
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.isOneTimeUseToken()).thenReturn(false);
        when(mockToken.getUserIdentifier()).thenReturn(userIdentifier);
        when(csrfUserContext.getUserIdentifier()).thenReturn(userIdentifier);
        when(mockToken.getTokenValue()).thenReturn(token);
        when(mockToken.getTokenTimeout()).thenReturn(10000L);
        when(mockToken.getTokenTimestamp()).thenReturn(new Date().getTime());
        when(mockToken.getResourceURL()).thenReturn(uri);
        when(requestContext.getRequestURL()).thenReturn(null);
        PowerMockito.mockStatic(SecureCompare.class);
        PowerMockito.when(SecureCompare.isEqual(Mockito.any(byte[].class), Mockito.any(byte[].class))).thenReturn(true);
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenOneTimeUseRemovedUsedAgainVerificationFail() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        CSRFUserContext csrfUserContext = Mockito.mock(CSRFUserContext.class);
        when(tokenVerificationContext.getUserContext()).thenReturn(csrfUserContext);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn(token);
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.getUserIdentifier()).thenReturn(userIdentifier);
        when(csrfUserContext.getUserIdentifier()).thenReturn(userIdentifier);
        when(mockToken.getTokenValue()).thenReturn(token);
        when(mockToken.getTokenTimeout()).thenReturn(100000L);
        when(mockToken.getTokenTimestamp()).thenReturn(new Date().getTime());
        when(mockToken.getResourceURL()).thenReturn(uri);
        when(requestContext.getRequestURL()).thenReturn(uri);
        when(mockToken.isOneTimeUseToken()).thenReturn(true);
        when(contextStore.removeItem(Mockito.eq(token))).thenReturn(mockToken);
        storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(null);
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenWithCompleteTokenContextVerificationPass() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        CSRFUserContext csrfUserContext = Mockito.mock(CSRFUserContext.class);
        when(tokenVerificationContext.getUserContext()).thenReturn(csrfUserContext);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn(token);
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.isOneTimeUseToken()).thenReturn(false);
        when(mockToken.getUserIdentifier()).thenReturn(userIdentifier);
        when(csrfUserContext.getUserIdentifier()).thenReturn(userIdentifier);
        when(mockToken.getTokenValue()).thenReturn(token);
        when(mockToken.getTokenTimeout()).thenReturn(100000L);
        when(mockToken.getTokenTimestamp()).thenReturn(new Date().getTime());
        when(mockToken.getResourceURL()).thenReturn(uri);
        when(requestContext.getRequestURL()).thenReturn(uri);
        Assert.assertTrue(storeBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenWithNoTokenContextVerificationFail() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        CSRFUserContext csrfUserContext = Mockito.mock(CSRFUserContext.class);
        when(tokenVerificationContext.getUserContext()).thenReturn(csrfUserContext);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestToken()).thenReturn(token);
        StoredToken mockToken = Mockito.mock(StoredToken.class);
        when(tokenStorageService.getTokenContextStore()).thenReturn(contextStore);
        when(contextStore.getItem(Mockito.eq(token))).thenReturn(mockToken);
        when(mockToken.isOneTimeUseToken()).thenReturn(false);
        when(mockToken.getUserIdentifier()).thenReturn(userIdentifier);
        when(csrfUserContext.getUserIdentifier()).thenReturn(userIdentifier);
        when(mockToken.getTokenValue()).thenReturn(token);
        when(mockToken.getTokenTimeout()).thenReturn(100000L);
        when(mockToken.getTokenTimestamp()).thenReturn(new Date().getTime());
        when(mockToken.getResourceURL()).thenReturn(uri);
        when(requestContext.getRequestURL()).thenReturn(uri);
        Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(token, null));
    }

    @Test
    public void test_verifyTokenInvalidTokensVerificationFail() throws CSRFTokenVerificationException {
        // Test lengths other than 32
        String charToken = token;
        for (int i = 0; i < 512; i++)
        {
            if (i%2 == 0)
                charToken = "T" + charToken;
            else charToken = charToken + "T";
            Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(charToken, null));
        }

        // Test special characters (+, =, / are valid)
        String[] specChar = {"\"","#","--","'",")","(","<","?",">","!","[","]",";","\\","..","&","#xA#xD","$","%","^","*","~","`","!",
                "|","%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A","-","{","}"};
        for (int i = 0; i < specChar.length; i++)
        {
            Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(specChar[i], null));
            Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(charToken + specChar[i], null));
            Assert.assertFalse(storeBasedCSRFTokenService.verifyToken(specChar[i] + charToken, null));
        }
    }

    @Test(expected = CSRFTokenServiceException.class)
    public void test_setUserSeedThrowsCSRFTokenServiceException() {
        storeBasedCSRFTokenService.setUserSeed("");
    }

    @Test(expected = CSRFTokenServiceException.class)
    public void test_setDefaultTimeoutThrowsCSRFTokenServiceException() {
        storeBasedCSRFTokenService.setDefaultTimeout(0L);
    }
}