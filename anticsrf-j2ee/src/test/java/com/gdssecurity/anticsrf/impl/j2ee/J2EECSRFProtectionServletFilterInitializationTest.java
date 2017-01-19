package com.gdssecurity.anticsrf.impl.j2ee;

import com.gdssecurity.anticsrf.spi.config.CSRFConfigException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.mockito.Mockito.when;


@RunWith(PowerMockRunner.class)
@PrepareForTest({HttpSession.class, FilterChain.class, ServletContext.class, FilterConfig.class, HttpServletRequest.class, HttpServletResponse.class})
public class J2EECSRFProtectionServletFilterInitializationTest {

    private static J2EECSRFProtectionServletFilter filter = new J2EECSRFProtectionServletFilter();
    private static FilterConfig filterConfig;
    private static ServletContext servletContext;


    @BeforeClass
    public static void setup() throws Exception {
        filter = new J2EECSRFProtectionServletFilter();
        servletContext = Mockito.mock(ServletContext.class);
        filterConfig = Mockito.mock(FilterConfig.class);

        when(filterConfig.getServletContext()).thenReturn(servletContext);
    }

    @Before
    public void before() {
        when(filterConfig.getInitParameter(Mockito.eq("antiCSRFConfigFile"))).thenReturn("./src/test/resources/sessionBasedConfig.xml");
    }

    @Test(expected = CSRFConfigException.class)
    public void test_configFileNull() throws javax.servlet.ServletException {
        when(filterConfig.getInitParameter(Mockito.eq("antiCSRFConfigFile"))).thenReturn(null);
        when(servletContext.getRealPath(Mockito.anyString())).thenReturn(null);
        filter.init(filterConfig);
    }

    @Test(expected = CSRFConfigException.class)
    public void test_configFileIncorrect() throws javax.servlet.ServletException {
        when(filterConfig.getInitParameter(Mockito.eq("antiCSRFConfigFile"))).thenReturn("MissingConfig.xml");
        filter.init(filterConfig);
    }

    @Test(expected = CSRFConfigException.class)
    public void test_defaultConfigFileMalformed() throws javax.servlet.ServletException {
        when(filterConfig.getInitParameter(Mockito.eq("antiCSRFConfigFile"))).thenReturn("");
        filter.init(filterConfig);
    }

//    @Test
//    public void test_VerifySessionConfigValues() throws javax.servlet.ServletException {
//        filter.init(filterConfig);
//    }
}