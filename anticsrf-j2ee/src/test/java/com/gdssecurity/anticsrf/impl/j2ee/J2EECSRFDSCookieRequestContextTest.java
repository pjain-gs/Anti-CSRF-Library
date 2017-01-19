package com.gdssecurity.anticsrf.impl.j2ee;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.when;


@RunWith(PowerMockRunner.class)
@PrepareForTest({J2EECSRFDSCookieRequestContext.class, HttpServletRequest.class})
public class J2EECSRFDSCookieRequestContextTest {

    private final static String tokenParamName = "TOKEN_PARAM";
    private final static String csrfHeader = "X-CSRF-TOKEN";
    private final static String token = "BASE64TOKEN0123456789+/=abcdefghijklmnopqrst";
    private final static String staticMethodToMock = "getRequest";

    private static J2EECSRFDSCookieRequestContext dsRequestContext = new J2EECSRFDSCookieRequestContext(tokenParamName, csrfHeader);

    @BeforeClass
    public static void setup() throws Exception {
        dsRequestContext = new J2EECSRFDSCookieRequestContext(tokenParamName, csrfHeader);
    }

    @Test
    public void test_getRequestToken() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getHeader(Mockito.eq(csrfHeader))).thenReturn(token);
        try {
            PowerMockito.spy(J2EECSRFDSCookieRequestContext.class);
            PowerMockito.doReturn(servletRequest).when(J2EECSRFDSCookieRequestContext.class, staticMethodToMock);
            Assert.assertEquals(dsRequestContext.getRequestToken(), token);
        } catch (Exception e) {
            System.out.println(e);
            Assert.assertTrue(false);
            return;
        }
    }

    @Test
    public void test_getRequestTokenNullRequest() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getHeader(Mockito.eq(csrfHeader))).thenReturn(null);
        try {
            PowerMockito.spy(J2EECSRFDSCookieRequestContext.class);
            PowerMockito.doReturn(servletRequest).when(J2EECSRFDSCookieRequestContext.class, staticMethodToMock);
            Assert.assertNull(dsRequestContext.getRequestToken());
        } catch (Exception e) {
            System.out.println(e);
            Assert.assertTrue(false);
            return;
        }
    }
}