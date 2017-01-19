
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

import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningException;
import com.gdssecurity.anticsrf.core.api.signing.CSRFSigningService;
import com.gdssecurity.anticsrf.core.rules.PatternProtectionRule;
import com.gdssecurity.anticsrf.spi.logging.CSRFLogger;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenGenerationContext;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenGenerationException;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenVerificationException;
import com.gdssecurity.anticsrf.spi.tokens.TokenVerificationContext;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.Date;

import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({SigningBasedCSRFTokenService.class, CSRFSigningService.class, CSRFLoggingService.class, CSRFTokenGenerationContext.class
        , TokenVerificationContext.class, CSRFRequestContext.class, PatternProtectionRule.class
        , CSRFUserContext.class, CSRFLogger.class})
public class SigningBasedCSRFTokenServiceTest {

    private final static String token = "BASE64TOKEN0123456789+/=abcdefghijklmnopqrst";
    private final static String uri = "URI";
    private final static String defaultUserSeed = "DEFAULTUSERSEED";
    private final static String userSeed = "USERSEED";
    private static final String hashedTokenFieldDelimiter = ":";
    private static final Long defaultTokenTimeout = 30000L;
    private static final Long tokenTimeout = 20000L;
    private static final String tokenTimeoutString = "20000";
    private static final String timestamp = String.valueOf(new Date().getTime());
    private static final String hashedToken = userSeed + uri + tokenTimeoutString + hashedTokenFieldDelimiter + timestamp;

    private CSRFSigningService signingService;
    private static CSRFLoggingService loggingService;
    private static CSRFTokenGenerationContext tokenGenerationContext;
    private static TokenVerificationContext tokenVerificationContext;
    private static CSRFRequestContext requestContext;
    private static CSRFUserContext userContext;
    private static PatternProtectionRule patternProtectionRule;
    private static CSRFLogger logger;

    private static SigningBasedCSRFTokenService signingBasedCSRFTokenService;

    @BeforeClass
    public static void setup() throws Exception {
        loggingService = Mockito.mock(CSRFLoggingService.class);
        logger = Mockito.mock(CSRFLogger.class);
        tokenGenerationContext = Mockito.mock(CSRFTokenGenerationContext.class);
        tokenVerificationContext = Mockito.mock(TokenVerificationContext.class);
        requestContext = Mockito.mock(CSRFRequestContext.class);
        patternProtectionRule = Mockito.mock(PatternProtectionRule.class);
        userContext = Mockito.mock(CSRFUserContext.class);
        when(tokenGenerationContext.getResourceURL()).thenReturn(uri);
        when(tokenGenerationContext.getUserContext()).thenReturn(null);
        when(tokenGenerationContext.getResourceProtectionRule()).thenReturn(null);
    }

    @Before
    public void before() throws CSRFSigningException {
        when(loggingService.getLogger(SigningBasedCSRFTokenService.class)).thenReturn(logger);
        doNothing().when(logger).warn(Mockito.anyString());
        doNothing().when(logger).debug(Mockito.anyString());
        signingService = Mockito.mock(CSRFSigningService.class);
        when(signingService.sign(Mockito.anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                return ((String) args[0]).replace(hashedTokenFieldDelimiter, "");
            }
        });
        when(signingService.verify(Mockito.anyString(), Mockito.anyString())).thenAnswer(new Answer<Boolean>() {
            @Override
            public Boolean answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                return (((String) args[0]).replace(hashedTokenFieldDelimiter, "")).compareTo((String) args[1]) == 0;
            }
        });
        signingBasedCSRFTokenService = new SigningBasedCSRFTokenService(signingService, loggingService);
        signingBasedCSRFTokenService.setUserSeed(defaultUserSeed);
        signingBasedCSRFTokenService.setDefaultTimeout(defaultTokenTimeout);
    }

    @Test(expected = CSRFTokenGenerationException.class)
    public void test_generateTokenThrowsCSRFSigningException() throws CSRFSigningException, CSRFTokenGenerationException {
        doThrow(new CSRFSigningException(""))
                .when(signingService)
                .sign(Mockito.anyString());
        signingBasedCSRFTokenService.generateToken(null);
    }

    @Test
    public void test_generateTokenNullContext() throws CSRFTokenGenerationException {
        String[] csrfTokenContents = (signingBasedCSRFTokenService.generateToken(null)).split(hashedTokenFieldDelimiter);
        Assert.assertEquals(csrfTokenContents.length, 2);
        Assert.assertEquals(csrfTokenContents[0], defaultUserSeed);
    }

    @Test
    public void test_generateTokenNullUrlNullProtectionRule() throws CSRFTokenGenerationException {
        when(tokenGenerationContext.getResourceProtectionRule()).thenReturn(null);
        when(tokenGenerationContext.getUserContext()).thenReturn(userContext);
        when(tokenGenerationContext.getResourceURL()).thenReturn(null);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        String[] csrfTokenContents = (signingBasedCSRFTokenService.generateToken(tokenGenerationContext)).split(hashedTokenFieldDelimiter);
        Assert.assertEquals(csrfTokenContents.length, 2);
        Assert.assertEquals(csrfTokenContents[0], userSeed);
    }

    @Test
    public void test_generateTokenNullUrl() throws CSRFTokenGenerationException {
        when(tokenGenerationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(tokenGenerationContext.getUserContext()).thenReturn(userContext);
        when(tokenGenerationContext.getResourceURL()).thenReturn(null);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(tokenTimeout);
        String[] csrfTokenContents = (signingBasedCSRFTokenService.generateToken(tokenGenerationContext)).split(hashedTokenFieldDelimiter);
        Assert.assertEquals(csrfTokenContents.length, 2);
        Assert.assertEquals(csrfTokenContents[0], userSeed + tokenTimeoutString);
    }

    @Test
    public void test_generateTokenNullProtectionRule() throws CSRFTokenGenerationException {
        when(tokenGenerationContext.getResourceProtectionRule()).thenReturn(null);
        when(tokenGenerationContext.getUserContext()).thenReturn(userContext);
        when(tokenGenerationContext.getResourceURL()).thenReturn(uri);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        String[] csrfTokenContents = (signingBasedCSRFTokenService.generateToken(tokenGenerationContext)).split(hashedTokenFieldDelimiter);
        Assert.assertEquals(csrfTokenContents.length, 2);
        Assert.assertEquals(csrfTokenContents[0], userSeed + uri);
    }

    @Test
    public void test_generateTokenNullUserSeed() throws CSRFTokenGenerationException {
        when(tokenGenerationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(tokenGenerationContext.getUserContext()).thenReturn(null);
        when(tokenGenerationContext.getResourceURL()).thenReturn(uri);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(tokenTimeout);
        when(tokenGenerationContext.getResourceURL()).thenReturn(uri);
        String[] csrfTokenContents = (signingBasedCSRFTokenService.generateToken(tokenGenerationContext)).split(hashedTokenFieldDelimiter);
        Assert.assertEquals(csrfTokenContents.length, 2);
        Assert.assertEquals(csrfTokenContents[0], defaultUserSeed + uri + tokenTimeoutString);
    }

    @Test
    public void test_generateTokenValidUrlProtectionRuleUserSeed() throws CSRFTokenGenerationException {
        when(tokenGenerationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(tokenGenerationContext.getUserContext()).thenReturn(userContext);
        when(tokenGenerationContext.getResourceURL()).thenReturn(uri);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(tokenTimeout);
        when(tokenGenerationContext.getResourceURL()).thenReturn(uri);
        String[] csrfTokenContents = (signingBasedCSRFTokenService.generateToken(tokenGenerationContext)).split(hashedTokenFieldDelimiter);
        Assert.assertEquals(csrfTokenContents.length, 2);
        Assert.assertEquals(csrfTokenContents[0], userSeed + uri + tokenTimeoutString);
    }

    @Test
    public void test_getTokenAlwaysReturnsNull() throws CSRFTokenGenerationException {
        Assert.assertNull(signingBasedCSRFTokenService.getToken());
        Assert.assertNull(signingBasedCSRFTokenService.getToken(null));
        Assert.assertNull(signingBasedCSRFTokenService.getToken(uri));
    }

    @Test
    public void test_verifyTokenExemptUrlVerificationPass() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(null);
        Assert.assertTrue(signingBasedCSRFTokenService.verifyToken(token, tokenVerificationContext));
    }

    @Test(expected = CSRFTokenVerificationException.class)
    public void test_verifyTokenBlankTokenVerificationFail() throws CSRFTokenVerificationException {
        Assert.assertFalse(signingBasedCSRFTokenService.verifyToken(null, null));
    }

    @Test(expected = CSRFTokenVerificationException.class)
    public void test_verifyTokenSigningServiceThrowsCSRFTokenVerificationException() throws CSRFTokenVerificationException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(tokenTimeout);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestURL()).thenReturn(uri);
        when(tokenVerificationContext.getUserContext()).thenReturn(userContext);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        signingBasedCSRFTokenService.verifyToken(hashedToken + hashedTokenFieldDelimiter + "EXTRA", tokenVerificationContext);
    }

    @Test
    public void test_verifyTokenTimeoutMisMatchVerificationFails() throws CSRFTokenVerificationException, CSRFSigningException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(defaultTokenTimeout);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestURL()).thenReturn(uri);
        when(tokenVerificationContext.getUserContext()).thenReturn(userContext);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        Assert.assertFalse(signingBasedCSRFTokenService.verifyToken(hashedToken, tokenVerificationContext));
        Mockito.verify(signingService, Mockito.times(1)).verify(Mockito.anyString(), Mockito.anyString());
    }

    @Test
    public void test_verifyTokenUrlMisMatchVerificationFails() throws CSRFTokenVerificationException, CSRFSigningException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(tokenTimeout);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestURL()).thenReturn("BADURI");
        when(tokenVerificationContext.getUserContext()).thenReturn(userContext);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        Assert.assertFalse(signingBasedCSRFTokenService.verifyToken(hashedToken, tokenVerificationContext));
        Mockito.verify(signingService, Mockito.times(1)).verify(Mockito.anyString(), Mockito.anyString());
    }

    @Test
    public void test_verifyTokenUserSeedMisMatchVerificationFails() throws CSRFTokenVerificationException, CSRFSigningException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(tokenTimeout);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestURL()).thenReturn(uri);
        when(tokenVerificationContext.getUserContext()).thenReturn(userContext);
        when(userContext.getUserIdentifier()).thenReturn("BADUSERSEED");
        Assert.assertFalse(signingBasedCSRFTokenService.verifyToken(hashedToken, tokenVerificationContext));
        Mockito.verify(signingService, Mockito.times(1)).verify(Mockito.anyString(), Mockito.anyString());
    }

    @Test
    public void test_verifyTokenTokenTimeStampMissingVerificationFails() throws CSRFTokenVerificationException, CSRFSigningException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(tokenTimeout);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestURL()).thenReturn(uri);
        when(tokenVerificationContext.getUserContext()).thenReturn(userContext);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        String tokenOmitTimeStamp = userSeed + uri + timestamp + hashedTokenFieldDelimiter + " ";
        when(signingService.verify(Mockito.anyString(), Mockito.anyString())).thenReturn(true);
        Assert.assertFalse(signingBasedCSRFTokenService.verifyToken(tokenOmitTimeStamp, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenExpiredTokenVerificationFails() throws CSRFTokenVerificationException, CSRFSigningException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(0L);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestURL()).thenReturn(uri);
        when(tokenVerificationContext.getUserContext()).thenReturn(userContext);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        String expiredToken = userSeed + uri + String.valueOf(0L) + hashedTokenFieldDelimiter + timestamp;
        when(signingService.verify(Mockito.anyString(), Mockito.anyString())).thenReturn(true);
        Assert.assertFalse(signingBasedCSRFTokenService.verifyToken(expiredToken, tokenVerificationContext));
    }

    @Test
    public void test_verifyTokenVerificationPass() throws CSRFTokenVerificationException, CSRFSigningException {
        when(tokenVerificationContext.getResourceProtectionRule()).thenReturn(patternProtectionRule);
        when(patternProtectionRule.getTokenTimeout()).thenReturn(tokenTimeout);
        when(tokenVerificationContext.getRequestContext()).thenReturn(requestContext);
        when(requestContext.getRequestURL()).thenReturn(uri);
        when(tokenVerificationContext.getUserContext()).thenReturn(userContext);
        when(userContext.getUserIdentifier()).thenReturn(userSeed);
        Assert.assertTrue(signingBasedCSRFTokenService
                .verifyToken(userSeed + uri + tokenTimeoutString + hashedTokenFieldDelimiter + String.valueOf(new Date().getTime())
                        , tokenVerificationContext));
        Mockito.verify(signingService, Mockito.times(1)).verify(Mockito.anyString(), Mockito.anyString());
    }

}