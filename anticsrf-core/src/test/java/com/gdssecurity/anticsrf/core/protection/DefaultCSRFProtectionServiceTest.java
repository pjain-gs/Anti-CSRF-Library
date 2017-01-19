
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

import com.gdssecurity.anticsrf.core.tokens.SimpleTokenGenerationContext;
import com.gdssecurity.anticsrf.core.tokens.SimpleTokenVerificationContext;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigService;
import com.gdssecurity.anticsrf.spi.logging.CSRFLoggingService;
import com.gdssecurity.anticsrf.spi.protection.CSRFProtectionException;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContext;
import com.gdssecurity.anticsrf.spi.request.CSRFRequestContextService;
import com.gdssecurity.anticsrf.spi.rules.CSRFResourceProtectionRule;
import com.gdssecurity.anticsrf.spi.rules.CSRFRulesService;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenGenerationException;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenService;
import com.gdssecurity.anticsrf.spi.tokens.CSRFTokenVerificationException;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContext;
import com.gdssecurity.anticsrf.spi.user.CSRFUserContextService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.*;


@RunWith(PowerMockRunner.class)
@PrepareForTest({DefaultCSRFProtectionServiceTest.class, CSRFTokenService.class, CSRFRulesService.class,
        CSRFConfigService.class, CSRFLoggingService.class, CSRFRequestContext.class,
        CSRFRequestContextService.class, CSRFUserContext.class, CSRFResourceProtectionRule.class,
        SimpleTokenVerificationContext.class, SimpleTokenGenerationContext.class})
public class DefaultCSRFProtectionServiceTest {

    private final static String token = "BASE64TOKEN0123456789+/=abcdefghijklmnopqrst";
    private final static String uri = "URI";

    private static CSRFTokenService tokenService;
    private static CSRFRulesService rulesService;
    private CSRFRequestContextService requestContextService;
    private static CSRFUserContextService userContextService;
    private static CSRFConfigService configService;
    private static CSRFLoggingService loggingService;
    private static CSRFRequestContext requestContext;
    private static CSRFUserContext userContext;
    private static DefaultCSRFProtectionService defaultCSRFProtectionService;

    @BeforeClass
    public static void setup() throws Exception {
        tokenService = Mockito.mock(CSRFTokenService.class);
        rulesService = Mockito.mock(CSRFRulesService.class);
        configService = Mockito.mock(CSRFConfigService.class);
        loggingService = Mockito.mock(CSRFLoggingService.class);
        requestContext = Mockito.mock(CSRFRequestContext.class);
    }

    @Before
    public void before() {
        requestContextService = Mockito.mock(CSRFRequestContextService.class);
        userContextService = null;
        userContext = null;
        defaultCSRFProtectionService = new DefaultCSRFProtectionService();
    }

    @Test(expected = CSRFProtectionException.class)
    public void test_initRepeatedCallThrowsException() {
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
    }

    @Test(expected = CSRFProtectionException.class)
    public void test_isVerifiedContextRequestNullContextServiceThrowsException() {
        defaultCSRFProtectionService.init(tokenService, rulesService, null, userContextService, configService, loggingService);
        defaultCSRFProtectionService.isVerifiedContextRequest();
    }

    @Test(expected = CSRFProtectionException.class)
    public void test_isVerifiedContextRequestNullContextThrowsException() {
        when(requestContextService.getCSRFRequestContext()).thenReturn(null);
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        defaultCSRFProtectionService.isVerifiedContextRequest();
    }

    @Test
    public void test_isVerifiedContextRequestNoUserContextReturnsTrue() throws Exception {
        when(requestContextService.getCSRFRequestContext()).thenReturn(requestContext);
        DefaultCSRFProtectionService spy = Mockito.spy(defaultCSRFProtectionService);
        doReturn(true).when(spy).isVerifiedRequest(Mockito.any(CSRFRequestContext.class), Mockito.any(CSRFUserContext.class));
        spy.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertTrue(spy.isVerifiedContextRequest());
    }

    @Test
    public void test_isVerifiedContextRequestNoUserContextReturnsFalse() {
        when(requestContextService.getCSRFRequestContext()).thenReturn(requestContext);
        DefaultCSRFProtectionService spy = Mockito.spy(defaultCSRFProtectionService);
        doReturn(false).when(spy).isVerifiedRequest(Mockito.any(CSRFRequestContext.class), Mockito.any(CSRFUserContext.class));
        spy.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertFalse(spy.isVerifiedContextRequest());
    }

    @Test
    public void test_isVerifiedContextRequestUserContextExistsReturnsTrue() {
        when(requestContextService.getCSRFRequestContext()).thenReturn(requestContext);
        userContext = Mockito.mock(CSRFUserContext.class);
        userContextService = Mockito.mock(CSRFUserContextService.class);
        when(userContextService.getUserContext()).thenReturn(userContext);
        DefaultCSRFProtectionService spy = Mockito.spy(defaultCSRFProtectionService);
        doReturn(true).when(spy).isVerifiedRequest(Mockito.any(CSRFRequestContext.class), Mockito.any(CSRFUserContext.class));
        spy.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertTrue(spy.isVerifiedContextRequest());
    }

    @Test
    public void test_isVerifiedContextRequestUserContextExistsReturnsFalse() {
        when(requestContextService.getCSRFRequestContext()).thenReturn(requestContext);
        userContext = Mockito.mock(CSRFUserContext.class);
        userContextService = Mockito.mock(CSRFUserContextService.class);
        when(userContextService.getUserContext()).thenReturn(userContext);
        DefaultCSRFProtectionService spy = Mockito.spy(defaultCSRFProtectionService);
        doReturn(false)
                .when(spy)
                .isVerifiedRequest(Mockito.any(CSRFRequestContext.class), Mockito.any(CSRFUserContext.class));
        spy.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertFalse(spy.isVerifiedContextRequest());
    }

    @Test(expected = CSRFProtectionException.class)
    public void test_isVerifiedRequestNullContextThrowsException() {
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        defaultCSRFProtectionService.isVerifiedRequest(null, userContext);
    }

    @Test(expected = CSRFProtectionException.class)
    public void test_isVerifiedRequestNestedMethodThrowsException() throws CSRFTokenVerificationException {
        CSRFResourceProtectionRule protectionRule = Mockito.mock(CSRFResourceProtectionRule.class);
        when(rulesService.getProtectionRuleForRequest(Mockito.eq(requestContext))).thenReturn(protectionRule);
        when(requestContext.getRequestToken()).thenReturn(token);
        when(requestContext.getRequestURL()).thenReturn(uri);
        doThrow(new CSRFTokenVerificationException(""))
                .when(tokenService)
                .verifyToken(Mockito.anyString(), Mockito.any(SimpleTokenVerificationContext.class));
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        defaultCSRFProtectionService.isVerifiedRequest(requestContext, userContext);
    }

    @Test
    public void test_isVerifiedRequestReturnsTrue() throws CSRFTokenVerificationException {
        CSRFResourceProtectionRule protectionRule = Mockito.mock(CSRFResourceProtectionRule.class);
        when(rulesService.getProtectionRuleForRequest(Mockito.eq(requestContext))).thenReturn(protectionRule);
        when(requestContext.getRequestToken()).thenReturn(token);
        when(requestContext.getRequestURL()).thenReturn(uri);
        doReturn(true)
                .when(tokenService)
                .verifyToken(Mockito.anyString(), Mockito.any(SimpleTokenVerificationContext.class));
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertTrue(defaultCSRFProtectionService.isVerifiedRequest(requestContext, userContext));
    }

    @Test
    public void test_isVerifiedRequestReturnsFalse() throws CSRFTokenVerificationException {
        CSRFResourceProtectionRule protectionRule = Mockito.mock(CSRFResourceProtectionRule.class);
        when(rulesService.getProtectionRuleForRequest(Mockito.eq(requestContext))).thenReturn(protectionRule);
        when(requestContext.getRequestToken()).thenReturn(token);
        when(requestContext.getRequestURL()).thenReturn(uri);
        doReturn(false)
                .when(tokenService)
                .verifyToken(Mockito.anyString(), Mockito.any(SimpleTokenVerificationContext.class));
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertFalse(defaultCSRFProtectionService.isVerifiedRequest(requestContext, userContext));
    }

    @Test(expected = CSRFProtectionException.class)
    public void test_generateTokenThrowsException() throws CSRFTokenGenerationException {
        doThrow(new CSRFTokenGenerationException(""))
                .when(tokenService)
                .generateToken();
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        defaultCSRFProtectionService.generateToken();
    }

    @Test
    public void test_generateTokenReturnsToken() throws CSRFTokenGenerationException {
        doReturn(token)
                .when(tokenService)
                .generateToken();
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertEquals(defaultCSRFProtectionService.generateToken(), token);
    }

    @Test
    public void test_generateResourceTokenExists() {
        DefaultCSRFProtectionService spy = Mockito.spy(defaultCSRFProtectionService);
        doReturn(token)
                .when(spy)
                .getToken(Mockito.eq(uri));
        spy.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertEquals(spy.generateResourceToken(uri, userContext), token);
    }

    @Test(expected = CSRFProtectionException.class)
    public void test_generateResourceTokenThrowsException() throws CSRFTokenGenerationException {
        DefaultCSRFProtectionService spy = Mockito.spy(defaultCSRFProtectionService);
        doReturn(null)
                .when(spy)
                .getToken(Mockito.eq(uri));
        CSRFResourceProtectionRule protectionRule = Mockito.mock(CSRFResourceProtectionRule.class);
        when(rulesService.getProtectionRuleForRequest(Mockito.eq(requestContext))).thenReturn(protectionRule);
        doThrow(new CSRFTokenGenerationException(""))
                .when(tokenService)
                .generateToken(Mockito.any(SimpleTokenGenerationContext.class));
        spy.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        spy.generateResourceToken(uri, userContext);
    }

    @Test
    public void test_generateResourceTokenReturnsToken() throws CSRFTokenGenerationException {
        DefaultCSRFProtectionService spy = Mockito.spy(defaultCSRFProtectionService);
        doReturn(null)
                .when(spy)
                .getToken(Mockito.eq(uri));
        CSRFResourceProtectionRule protectionRule = Mockito.mock(CSRFResourceProtectionRule.class);
        when(rulesService.getProtectionRuleForRequest(Mockito.eq(requestContext))).thenReturn(protectionRule);
        doReturn(token)
                .when(tokenService)
                .generateToken(Mockito.any(SimpleTokenGenerationContext.class));
        spy.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertEquals(spy.generateResourceToken(uri, userContext), token);
    }

    @Test
    public void test_getTokenNoUrlReturnsToken() throws CSRFTokenGenerationException {
        DefaultCSRFProtectionService spy = Mockito.spy(defaultCSRFProtectionService);
        doReturn(false)
                .when(spy)
                .hasUrlSpecificConfig(Mockito.anyString());
        doReturn(token)
                .when(tokenService)
                .getToken((String) Mockito.isNull());
        spy.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertEquals(spy.getToken(null), token);
    }

    @Test
    public void test_getTokenSpecificUrlReturnsToken() throws CSRFTokenGenerationException {
        DefaultCSRFProtectionService spy = Mockito.spy(defaultCSRFProtectionService);
        doReturn(true)
                .when(spy)
                .hasUrlSpecificConfig(Mockito.anyString());
        doReturn(token)
                .when(tokenService)
                .getToken(Mockito.eq(uri));
        spy.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertEquals(spy.getToken(uri), token);
    }

    @Test
    public void test_hasUrlSpecificConfigNoUrl() {
        List<Map.Entry<String, Long>> specificUrls = new ArrayList<Map.Entry<String, Long>>();
        when(configService.getUrlSpecificRuleEntries()).thenReturn(specificUrls);
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertFalse(defaultCSRFProtectionService.hasUrlSpecificConfig(null));
    }

    @Test
    public void test_hasUrlSpecificConfigReturnsFalse() {
        List<Map.Entry<String, Long>> specificUrls = new ArrayList<Map.Entry<String, Long>>();
        when(configService.getUrlSpecificRuleEntries()).thenReturn(specificUrls);
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertFalse(defaultCSRFProtectionService.hasUrlSpecificConfig(uri));
    }

    @Test
    public void test_hasUrlSpecificConfigReturnsTrue() {
        List<Map.Entry<String, Long>> specificUrls = new ArrayList<Map.Entry<String, Long>>();
        specificUrls.add(new AbstractMap.SimpleImmutableEntry<String, Long>("OTHERURI", 0L));
        specificUrls.add(new AbstractMap.SimpleImmutableEntry<String, Long>(uri, 0L));
        when(configService.getUrlSpecificRuleEntries()).thenReturn(specificUrls);
        defaultCSRFProtectionService.init(tokenService, rulesService, requestContextService, userContextService, configService, loggingService);
        Assert.assertTrue(defaultCSRFProtectionService.hasUrlSpecificConfig(uri));
    }

}