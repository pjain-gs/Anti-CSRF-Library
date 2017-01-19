package com.gdssecurity.anticsrf.impl.j2ee;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.when;


@RunWith(PowerMockRunner.class)
@PrepareForTest(HttpServletRequest.class)
public class J2EEHelperTest {

    @Test
    public void test_getRequestUrl() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getRequestURI()).thenReturn("URI");
        try {
            Assert.assertEquals(J2EEHelper.getRequestURL(servletRequest), "URI");
        } catch (Exception e) {
            System.out.println(e);
            Assert.assertTrue(false);
            return;
        }
    }

    @Test
    public void test_getRequestUrlReturnsNull() throws Exception {
        try {
            Assert.assertNull(J2EEHelper.getRequestURL(null));
        } catch (Exception e) {
            System.out.println(e);
            Assert.assertTrue(false);
            return;
        }
    }

    @Test
    public void test_getRequestUrlReturnsBlank() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getRequestURI()).thenReturn("");
        when(servletRequest.getQueryString()).thenReturn("");
        try {
            Assert.assertEquals(J2EEHelper.getRequestURL(servletRequest), "");
        } catch (Exception e) {
            System.out.println(e);
            Assert.assertTrue(false);
            return;
        }
    }

    @Test
    public void test_getRequestUrlReturnsQueryString() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getRequestURI()).thenReturn("/D1/URI%3F/a%3F+b;jsessionid=S%3F+ID");
        when(servletRequest.getQueryString()).thenReturn("param1=val1&param2=val2");
        try {
            Assert.assertEquals(J2EEHelper.getRequestURL(servletRequest), "/D1/URI%3F/a%3F+b;jsessionid=S%3F+ID?param1=val1&param2=val2");
        } catch (Exception e) {
            System.out.println(e);
            Assert.assertTrue(false);
            return;
        }
    }

    @Test
    public void test_getRequestUrlReturnsNoQueryString() throws Exception {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        when(servletRequest.getRequestURI()).thenReturn("/D1/URI%3F/a%3F+b;jsessionid=S%3F+ID");
        when(servletRequest.getQueryString()).thenReturn("");
        try {
            Assert.assertEquals(J2EEHelper.getRequestURL(servletRequest), "/D1/URI%3F/a%3F+b;jsessionid=S%3F+ID");
        } catch (Exception e) {
            System.out.println(e);
            Assert.assertTrue(false);
            return;
        }
    }
}