
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

package com.gdssecurity.anticsrf.core.rules;

import org.junit.Assert;
import org.junit.Test;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RulesHelperTest {

    private final static String uri = "URI";
    private static Long defaultTokenTimeout = 0L;


    @Test
    public void test_getProtectionRulesEmptyRuleEntries() {
        List<Map.Entry<String, Long>> protectionRuleEntries = new ArrayList<Map.Entry<String, Long>>();
        Assert.assertTrue(RulesHelper.getProtectionRules(protectionRuleEntries, defaultTokenTimeout).isEmpty());
    }

    @Test
    public void test_getProtectionRulesNoUrl() {
        List<Map.Entry<String, Long>> protectionRuleEntries = new ArrayList<Map.Entry<String, Long>>();
        protectionRuleEntries.add(new AbstractMap.SimpleImmutableEntry<String, Long>(null, defaultTokenTimeout));
        Assert.assertTrue(RulesHelper.getProtectionRules(protectionRuleEntries, defaultTokenTimeout).isEmpty());
    }

    @Test
    public void test_getProtectionRulesNoRuleList() {
        Assert.assertTrue(RulesHelper.getProtectionRules(null, defaultTokenTimeout).isEmpty());
    }

    @Test
    public void test_getProtectionRulesNoTokenTimeout() {
        List<Map.Entry<String, Long>> protectionRuleEntries = new ArrayList<Map.Entry<String, Long>>();
        protectionRuleEntries.add(new AbstractMap.SimpleImmutableEntry<String, Long>(uri, null));
        List<PatternProtectionRule> pRules = RulesHelper.getProtectionRules(protectionRuleEntries, defaultTokenTimeout);
        Assert.assertTrue(pRules.size() == 1);
        Assert.assertTrue(pRules.get(0).getTokenTimeout() == null);
    }

    @Test
    public void test_getProtectionRulesDuplicateEntriesExist() {
        List<Map.Entry<String, Long>> protectionRuleEntries = new ArrayList<Map.Entry<String, Long>>();
        protectionRuleEntries.add(new AbstractMap.SimpleImmutableEntry<String, Long>(uri, defaultTokenTimeout));
        protectionRuleEntries.add(new AbstractMap.SimpleImmutableEntry<String, Long>(uri, defaultTokenTimeout));
        List<PatternProtectionRule> pRules = RulesHelper.getProtectionRules(protectionRuleEntries, defaultTokenTimeout);
        Assert.assertTrue(pRules.size() == 2);
        Assert.assertEquals(pRules.get(0).getResourceURL(), pRules.get(1).getResourceURL());
        Assert.assertEquals(pRules.get(0).getTokenTimeout(), pRules.get(1).getTokenTimeout());
    }

    @Test
    public void test_getProtectionRulesValidEntries() {
        List<Map.Entry<String, Long>> protectionRuleEntries = new ArrayList<Map.Entry<String, Long>>();
        protectionRuleEntries.add(new AbstractMap.SimpleImmutableEntry<String, Long>(uri, defaultTokenTimeout));
        protectionRuleEntries.add(new AbstractMap.SimpleImmutableEntry<String, Long>("OTHERURI", defaultTokenTimeout));
        List<PatternProtectionRule> pRules = RulesHelper.getProtectionRules(protectionRuleEntries, defaultTokenTimeout);
        Assert.assertTrue(pRules.size() == 2);
        Assert.assertEquals(pRules.get(0).getTokenTimeout(), defaultTokenTimeout);
        Assert.assertEquals(pRules.get(0).getResourceURL(), uri);
        Assert.assertEquals(pRules.get(1).getTokenTimeout(), defaultTokenTimeout);
        Assert.assertEquals(pRules.get(1).getResourceURL(), "OTHERURI");
    }

    @Test
    public void test_getExemptionRulesNoUrl() {
        List<String> exemptionRuleEntries = new ArrayList<String>();
        exemptionRuleEntries.add(null);
        Assert.assertTrue(RulesHelper.getExemptionRules(exemptionRuleEntries).isEmpty());
    }

    @Test
    public void test_getExemptionRulesNoRuleList() {
        Assert.assertTrue(RulesHelper.getExemptionRules(null).isEmpty());
    }

    @Test
    public void test_getExemptionRulesDuplicateEntriesExist() {
        List<String> exemptionRuleEntries = new ArrayList<String>();
        exemptionRuleEntries.add(uri);
        exemptionRuleEntries.add(uri);
        List<PatternExemptionRule> eRules = RulesHelper.getExemptionRules(exemptionRuleEntries);
        Assert.assertTrue(eRules.size() == 2);
        Assert.assertEquals(eRules.get(0).getResourceURL(), eRules.get(1).getResourceURL());
    }

    @Test
    public void test_getExemptionRulesValidEntries() {
        List<String> exemptionRuleEntries = new ArrayList<String>();
        exemptionRuleEntries.add(uri);
        exemptionRuleEntries.add("OTHERURI");
        List<PatternExemptionRule> eRules = RulesHelper.getExemptionRules(exemptionRuleEntries);
        Assert.assertTrue(eRules.size() == 2);
        Assert.assertEquals(eRules.get(0).getResourceURL(), uri);
        Assert.assertEquals(eRules.get(1).getResourceURL(), "OTHERURI");
    }

    @Test
    public void test_findRuleForResourceNoUrl() {
        List<PatternRule> rulesList = new ArrayList<PatternRule>();
        Assert.assertNull(RulesHelper.findRuleForResource(null, rulesList));
    }

    @Test
    public void test_findRuleForResourceNoRuleList() {
        Assert.assertNull(RulesHelper.findRuleForResource(uri, null));
    }

    @Test
    public void test_findRuleForResourceNullRules() {
        List<PatternRule> rulesList = new ArrayList<PatternRule>();
        rulesList.add(null);
        Assert.assertNull(RulesHelper.findRuleForResource(uri, rulesList));
    }

    @Test
    public void test_findRuleForResourcePatternProtectionRulesList() {
        List<PatternProtectionRule> rulesList = new ArrayList<PatternProtectionRule>();
        rulesList.add(null);
        PatternProtectionRule rule = new PatternProtectionRule(uri, defaultTokenTimeout);
        rulesList.add(rule);
        rulesList.add(new PatternProtectionRule("OTHERURI", defaultTokenTimeout));
        Assert.assertEquals(RulesHelper.findRuleForResource(uri, rulesList), rule);
    }

    @Test
    public void test_findRuleForResourcePatternExemptionRulesList() {
        List<PatternExemptionRule> rulesList = new ArrayList<PatternExemptionRule>();
        rulesList.add(null);
        PatternExemptionRule rule = new PatternExemptionRule(uri);
        rulesList.add(rule);
        rulesList.add(new PatternExemptionRule("OTHERURI"));
        Assert.assertEquals(RulesHelper.findRuleForResource(uri, rulesList), rule);
    }
}