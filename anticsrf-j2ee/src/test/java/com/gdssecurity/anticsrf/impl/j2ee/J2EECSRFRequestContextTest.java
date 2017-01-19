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
@PrepareForTest({J2EECSRFRequestContext.class, HttpServletRequest.class})
public class J2EECSRFRequestContextTest {

    private final static String tokenParamName = "TOKEN_PARAM";
    private final static String uri = "URI";
    private final static String token = "BASE64TOKEN0123456789+/=abcdefghijklmnopqrst";
    private final static String staticMethodToMock = "getRequest";

    private static J2EECSRFRequestContext requestContext = new J2EECSRFRequestContext(tokenParamName);

    @BeforeClass
    public static void setup() throws Exception {
        requestContext = new J2EECSRFRequestContext(tokenParamName);
    }

    @Test
    public void test_getRequestURL() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getRequestURI()).thenReturn(uri);
        try {
            PowerMockito.spy(J2EECSRFRequestContext.class);
            PowerMockito.doReturn(servletRequest).when(J2EECSRFRequestContext.class, staticMethodToMock);
            Assert.assertEquals(requestContext.getRequestURL(), uri);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            Assert.assertTrue(false);
            return;
        }
    }

    @Test
    public void test_getRequestURLReturnsNull() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getRequestURI()).thenReturn(uri);
        try {
            PowerMockito.spy(J2EECSRFRequestContext.class);
            PowerMockito.doReturn(null).when(J2EECSRFRequestContext.class, staticMethodToMock);
            Assert.assertNull(requestContext.getRequestURL());
        } catch (Exception e) {
            System.out.println(e.getMessage());
            Assert.assertTrue(false);
            return;
        }
    }

    @Test
    public void test_getRequestToken() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getParameter(Mockito.eq(tokenParamName))).thenReturn(token);
        try {
            PowerMockito.spy(J2EECSRFRequestContext.class);
            PowerMockito.doReturn(servletRequest).when(J2EECSRFRequestContext.class, staticMethodToMock);
            Assert.assertEquals(requestContext.getRequestToken(), token);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            Assert.assertTrue(false);
            return;
        }
    }

    @Test
    public void test_getRequestTokenReturnsNull() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getParameter(Mockito.eq(tokenParamName))).thenReturn(token);
        try {
            PowerMockito.spy(J2EECSRFRequestContext.class);
            PowerMockito.doReturn(null).when(J2EECSRFRequestContext.class, staticMethodToMock);
            Assert.assertNull(requestContext.getRequestToken());
        } catch (Exception e) {
            System.out.println(e.getMessage());
            Assert.assertTrue(false);
            return;
        }
    }
}