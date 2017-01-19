package com.gdssecurity.anticsrf.impl.j2ee;

import com.gdssecurity.anticsrf.core.tokens.StoredToken;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;

public class J2EESessionTokenContextStoreTest {

    private final static String token = "BASE64TOKEN0123456789+/=abcdefghijklmnopqrst";

    private static J2EESessionTokenContextStore testStore;

    @Before
    public void before() {
        testStore = new J2EESessionTokenContextStore(new HashMap<String, Object>());
    }

    @Test
    public void test_emptyTrue() {
        Assert.assertTrue(testStore.empty());
    }

    @Test
    public void test_emptyFalse() {
        testStore.setItem(token, new StoredToken(token, null, null, null, false, null));
        Assert.assertFalse(testStore.empty());
    }

    @Test
    public void test_getItemExistsTrue() {
        StoredToken storedToken = new StoredToken(token, null, null, null, false, null);
        testStore.setItem(token, storedToken);
        Assert.assertEquals(testStore.getItem(token), storedToken);
    }

    @Test
    public void test_getItemExistsFalse() {
        Assert.assertNull(testStore.getItem(token));
    }

    @Test
    public void test_getStoredTokenNullUrlOneToken() {
        //using this method with a null url is equivalent to obtaining the sitewide token
        StoredToken storedToken = new StoredToken(token, null, null, null, false, null);
        testStore.setItem(token, storedToken);
        Assert.assertEquals(testStore.getStoredToken(null), storedToken);
    }

    @Test
    public void test_getStoredTokenNullUrlBlankUrlOneToken() {
        //using this method with a null url is equivalent to obtaining the sitewide token
        StoredToken storedToken = new StoredToken(token, null, null, null, false, null);
        testStore.setItem(token, storedToken);
        Assert.assertEquals(testStore.getStoredToken(null), testStore.getStoredToken(""));
    }

    @Test
    public void test_getStoredTokenNullUrlTwoTokens() {
        //using this method with a null url is equivalent to obtaining the sitewide token
        testStore.setItem("TOKENWITHURL", new StoredToken("TOKENWITHURL", "URI", null, null, false, null));
        StoredToken storedToken = new StoredToken(token, null, null, null, false, null);
        testStore.setItem(token, storedToken);
        Assert.assertEquals(testStore.getStoredToken(null), storedToken);
    }

    @Test
    public void test_getStoredTokenWithUrlOneToken() {
        StoredToken storedToken = new StoredToken(token, "URI", null, null, false, null);
        testStore.setItem(token, storedToken);
        Assert.assertEquals(testStore.getStoredToken("URI"), storedToken);
    }

//    @Test
//    public void test_getStoredTokenWithUrlThreeTokens() {
//        testStore.setItem("TOKENWITHURL", new StoredToken("TOKENWITHURL", "URI", null, null, false, null));
//        StoredToken storedToken = new StoredToken(token, "URI", null, null, false, null);
//        testStore.setItem(token, storedToken);
//        testStore.setItem("ANOTHERTOKENWITHURL", new StoredToken("ANOTHERTOKENWITHURL", "ANOTHERURI", null, null, false, null));
//        Assert.assertEquals(testStore.getStoredToken("URI"), storedToken);
//    }

    @Test
    public void test_setItemMatch() {
        StoredToken storedToken = new StoredToken(token, null, null, null, false, null);
        testStore.setItem(token, storedToken);
        Assert.assertTrue(testStore.hasItem(token));
    }

    @Test
    public void test_hasItemExistsFalse() {
        Assert.assertFalse(testStore.hasItem("BADTOKEN0123456789+/=abcdefghijk"));
    }

    @Test
    public void test_hasItemNonEmptyExistsFalse() {
        StoredToken storedToken = new StoredToken(token, null, null, null, false, null);
        testStore.setItem(token, storedToken);
        Assert.assertFalse(testStore.hasItem("BADTOKEN0123456789+/=abcdefghijk"));
    }

    @Test
    public void test_removeItemExistsTrue() {
        StoredToken storedToken = new StoredToken(token, null, null, null, false, null);
        testStore.setItem(token, storedToken);
        Assert.assertEquals(testStore.removeItem(token), storedToken);
        Assert.assertFalse(testStore.hasItem(token));
    }

    @Test
    public void test_removeItemNonExistent() {
        StoredToken storedToken = new StoredToken(token, null, null, null, false, null);
        testStore.setItem(token, storedToken);
        testStore.removeItem(token);
        Assert.assertNull(testStore.removeItem(token));
    }

}