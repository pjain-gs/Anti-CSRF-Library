package com.gdssecurity.anticsrf.impl.j2ee;

import com.gdssecurity.anticsrf.impl.j2ee.util.J2EECSRFConstants;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.session.HashSessionIdManager;
import org.eclipse.jetty.server.session.HashSessionManager;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.owasp.encoder.Encode;

import javax.servlet.DispatcherType;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.HttpCookie;
import java.util.EnumSet;
import java.util.List;


public class J2EEHybridServletFilterTest {

    public static class RootServlet extends HttpServlet {
        @Override
        public void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.getWriter().append("INDEX");
        }
    }

    public static class TestServlet extends HttpServlet {
        @Override
        public void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.getWriter().append("SUCCESS");
        }
    }

    private static Server tester;
    private static HttpClient hc;

    private final static String badToken = "BADTOKEN0123456789+/=abcdefghijklmnopqrstuvw";
    private final static String reqParam = "tok";
    private final static String reqHeader = "X-CSRF-Token";
    private final static String sessionStoreKey = "SESSION_TOKEN_STORE";

    @Before
    public void setupServer() throws Exception {
        System.out.println("-------------------------------------STARTING JETTY SERVER-------------------------------------");

        tester = new Server(8080);

        // Specify the Session ID Manager
        HashSessionIdManager idmanager = new HashSessionIdManager();
        tester.setSessionIdManager(idmanager);

        // Sessions are bound to a context.
        ContextHandler context = new ContextHandler("/");
        tester.setHandler(context);

        // Create the SessionHandler (wrapper) to handle the sessions
        HashSessionManager manager = new HashSessionManager();
        SessionHandler sessions = new SessionHandler(manager);
        context.setHandler(sessions);

        // Add the servlets and filter. A root servlet to establish a session, and a test servlet that should be reached
        // only if filter verification is true
        ServletContextHandler servletContextHandler = new ServletContextHandler(tester, "/", true, true);
        servletContextHandler.addServlet(RootServlet.class, "/");
        servletContextHandler.addServlet(TestServlet.class, "/url");
        servletContextHandler.addFilter(J2EEHybridServletFilter.class, "/*",  EnumSet.of(DispatcherType.REQUEST))
                .setInitParameter("antiCSRFConfigFile", "./src/test/resources/hybridConfig.xml");

        tester.start();

        hc = new HttpClient();
        hc.setConnectTimeout(20000);
        hc.start();
    }

    @After
    public void shutdownServer() throws Exception {
        System.out.println("-------------------------------------SHUTTING DOWN JETTY SERVER-------------------------------------");
        tester.stop();
        hc.stop();
    }

    @Test
    public void test_exempt() {
        try {
            ContentResponse response = hc.GET("http://localhost:8080/");
            Assert.assertEquals(HttpServletResponse.SC_OK, response.getStatus());
        }
        catch (Exception e)
        {
            System.out.println(e + e.getMessage());
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void test_match_sessionBased() {
        try {
            hc.GET("http://localhost:8080/");

            List<HttpCookie> cookies = hc.getCookieStore().getCookies();
            String tok = "";
            for (int i = 0; i < cookies.size(); i++) {
                if (cookies.get(i).getName().equals(J2EECSRFConstants.DEFAULT_COOKIE_NAME)) {
                    tok = Encode.forHtmlAttribute(cookies.get(i).getValue());
                    break;
                }
            }

            ContentResponse response = hc.newRequest("http://localhost:8080/url")
                    .method(HttpMethod.GET)
                    .param(reqParam, tok)
                    .send();

            Assert.assertEquals(HttpServletResponse.SC_OK, response.getStatus());
            Assert.assertEquals("SUCCESS", response.getContentAsString());
        }
        catch (Exception e)
        {
            System.out.println(e + e.getMessage());
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void test_match_cookieBased() {
        try {
            hc.GET("http://localhost:8080/");
            List<HttpCookie> cookies = hc.getCookieStore().getCookies();
            String tok = "";
            for (int i = 0; i < cookies.size(); i++) {
                if (cookies.get(i).getName().equals(J2EECSRFConstants.DEFAULT_COOKIE_NAME)) {
                    tok = Encode.forHtml(cookies.get(i).getValue());
                    break;
                }
            }

            ContentResponse response = hc.newRequest("http://localhost:8080/url")
                    .method(HttpMethod.GET)
                    .header(reqHeader, tok)
                    .send();

            Assert.assertEquals(HttpServletResponse.SC_OK, response.getStatus());
            Assert.assertEquals("SUCCESS", response.getContentAsString());
        }
        catch (Exception e)
        {
            System.out.println(e + e.getMessage());
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void test_mismatch_sessionBased() {
        try {
            hc.GET("http://localhost:8080/");

            List<HttpCookie> cookies = hc.getCookieStore().getCookies();
            String tok = "";
            for (int i = 0; i < cookies.size(); i++) {
                if (cookies.get(i).getName().equals(J2EECSRFConstants.DEFAULT_COOKIE_NAME)) {
                    tok = Encode.forHtmlAttribute(cookies.get(i).getValue());
                    break;
                }
            }

            ContentResponse response = hc.newRequest("http://localhost:8080/url")
                    .method(HttpMethod.GET)
                    .param(reqParam, Encode.forHtmlAttribute(badToken))
                    .send();

            Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
            Assert.assertEquals("Request failed", response.getReason());

            response = hc.newRequest("http://localhost:8080/url")
                    .method(HttpMethod.GET)
                    .param(reqParam, Encode.forHtmlAttribute(badToken))
                    .header(reqHeader, tok)
                    .send();

            Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
            Assert.assertEquals("Request failed", response.getReason());
        }
        catch (Exception e)
        {
            System.out.println(e + e.getMessage());
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void test_mismatch_cookieBased() {
        try {
            hc.GET("http://localhost:8080/");

            String tok = Encode.forHtml(badToken);

            ContentResponse response =  hc.newRequest("http://localhost:8080/url")
                    .method(HttpMethod.GET)
                    .header(reqHeader, tok)
                    .send();

            Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
            Assert.assertEquals("Request failed", response.getReason());
        }
        catch (Exception e)
        {
            System.out.println(e + e.getMessage());
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void test_missing() {
        try {
            ContentResponse response = hc.GET("http://localhost:8080/url");
            Assert.assertEquals("Request failed", response.getReason());
            Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        }
        catch (Exception e)
        {
            System.out.println(e + e.getMessage());
            e.printStackTrace();
            Assert.assertTrue(false);
        }
    }
}