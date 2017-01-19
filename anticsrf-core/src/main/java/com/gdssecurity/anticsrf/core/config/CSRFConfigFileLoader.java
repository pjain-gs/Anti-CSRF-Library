
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

package com.gdssecurity.anticsrf.core.config;

import com.gdssecurity.anticsrf.core.tokens.CSRFTokenRecollectionStrategy;
import com.gdssecurity.anticsrf.core.util.Constants;
import com.gdssecurity.anticsrf.spi.config.CSRFConfigException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.*;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * Handles the loading and parsing of the configuration file
 */
class CSRFConfigFileLoader {

    private static final Logger LOG = Logger.getLogger(CSRFConfigFileLoader.class.getName());

    private Properties csrfConfig = new Properties(); // Contains the mandatory properties in the config file.
    private List<String> exemptUrls = new ArrayList<String>(); // List of URLs in the config file that do not to be validated with a CSRF token.
    private List<Map.Entry<String, Long>> urlSpecificConfig = new ArrayList<Map.Entry<String, Long>>(); // List of URLs in the config file with independent tokens.
    private HashMap<String, Integer> oneTimeUseConfig = new HashMap<String, Integer>(); // Map of URLs with one-time use tokens in config file, with entries specified as <url, (int)0> as default.

    protected CSRFConfigFileLoader(String configFilename) {
        loadConfigFile(configFilename);
    }

    /**
     * Loads the specified configuration file as a file input stream. Uses a default filename is one is not supplied.
     * @param configFilename        configuration file path name.
     * @throws CSRFConfigException  if the configuration file could not be found or a failure occurred during reading.
     */
    protected void loadConfigFile(String configFilename) throws CSRFConfigException {
        String configFilePath = (StringUtils.isNotBlank(configFilename) ? configFilename : Constants.CONFIGNAME);

        try {
            FileInputStream fis = new FileInputStream(configFilePath);
            loadConfigStream(fis);
            fis.close();
        } catch (FileNotFoundException ex) {
            String err = "CSRF Configuration file is not found, exception=" + ex.getMessage();
            LOG.severe(err);
            throw new CSRFConfigException(err);
        } catch (IOException ex) {
            String err = "Failed to properly read CSRF Configuration file" +
                    ", exception=" + ex.getMessage();
            LOG.severe(err);
            throw new CSRFConfigException(err);
        }
    }

    /**
     * Builds a DOM from the input stream to parse the XML configuration file and set all configuration properties.
     * Fatal error is thrown if the input stream contains a DOCTYPE declaration. Input stream should not include
     * general external entities.
     * @param is                    input stream used to build the DOM.
     * @throws CSRFConfigException  if a failure occurs during reading or parsing of the input stream, or if invalid
     *                              attributes are specified in the configuration file.
     */
    protected void loadConfigStream(InputStream is) throws CSRFConfigException {
        LOG.info("Loading XML Config File");
        try {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

            try {
                dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); // A fatal error is thrown if the incoming document contains a DOCTYPE declaration.
                dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false); // Do not include external general entities.
            }
            catch (ParserConfigurationException e) {
                LOG.warning("Could not set parser feature " + e);
            }

            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(is);
            doc.getDocumentElement().normalize();

            // Get the protection mode from the config.
            NodeList nl = doc.getElementsByTagName(Constants.CONF_MODE);
            Node node = nl.item(0);

            String mode = Constants.MODES.session.toString(); // Session based protection is the default mode.

            if (node != null) {
                mode = node.getFirstChild().getNodeValue();
            }

            Constants.MODES.valueOf(mode); // Make sure it is an existent mode.
            csrfConfig.setProperty(Constants.CONF_MODE, mode);

            Element docElement = doc.getDocumentElement();

            // Load any custom logging configuration properties.
            loadLoggingConfiguration(docElement);

            // Depending on the protection mode, configuration loading will be handled differently for session mode and HMAC mode.
            if (CSRFConfigFileLoaderUtil.isHmacMode(csrfConfig)) {
                handleHMACConfigLoading(doc);
            } else if (CSRFConfigFileLoaderUtil.isSessionMode(csrfConfig)) {
                handleSessionConfigLoading(doc);
            }

            readXmlUrlListing(docElement, Constants.CONF_EXEMPTURLS); // read all exempt URLs.

            // Check for a specified token request attribute value.
            String tokenRequestAttribute = readElementTextValue(docElement, Constants.CONF_TOKEN_REQATTR);
            if (tokenRequestAttribute.equals("")) {
                tokenRequestAttribute = Constants.CONF_DEFAULT_TOKEN_REQATTR;
            }

            // Check for a specified token request parameter value.
            String tokenRequestParameter = readElementTextValue(docElement, Constants.CONF_TOKEN_PARAM);
            if (tokenRequestParameter.equals("")) {
                tokenRequestParameter = Constants.CONF_DEFAULT_TOKEN_PARAM;
            }

            // Check for a specified monitor mode value. Throw exception if not specified.
            String monitorMode = readElementAttributeTextValue(docElement, Constants.CONF_MONITORMODE, "enabled");
            if (monitorMode.equals("")) {
                monitorMode = "no"; // Disabled by default.
            }
            if (!monitorMode.equals("yes") && !monitorMode.equals("no")) {
                throw new CSRFConfigException("Invalid monitormode attribute entered. " +
                        "We are expecting either 'yes' or 'no'. EnteredValue=" + monitorMode);
            }

            // Check for a specified error value. Throw exception if not specified.
            String errorValue = "";
            String errorMode = readElementAttributeTextValue(docElement, Constants.CONF_ERROR, "mode");
            if (errorMode == null) {
                errorMode = "";
            }
            if (errorMode.equals("redirect") || errorMode.equals("forward")) {
                errorValue = CSRFConfigFileLoaderUtil.getValidatedUrl(readElementTextValue(docElement, Constants.CONF_ERROR));
            } else if (errorMode.equals("status_code")) {
                errorValue = readElementTextValue(docElement, Constants.CONF_ERROR);
                if (!CSRFConfigFileLoaderUtil.validateTimeout(errorValue, LOG)) {
                    throw new CSRFConfigException("Invalid StatusCode passed within configuration error attribute. Submitted StatusCode=" + errorValue);
                }
            }

            csrfConfig.setProperty(Constants.CONF_ERROR, errorMode);
            csrfConfig.setProperty(Constants.CONF_ERRORVAL, errorValue);
            csrfConfig.setProperty(Constants.CONF_TOKEN_PARAM, tokenRequestParameter);
            csrfConfig.setProperty(Constants.CONF_TOKEN_REQATTR, tokenRequestAttribute);
            csrfConfig.setProperty(Constants.CONF_MONITORMODE, monitorMode);

            printConfiguration();

        } catch (ParserConfigurationException ex) {
            String err = "Failed to parse CSRF Configuration file, exception=" + ex.getMessage();
            LOG.severe(err);
            throw new CSRFConfigException(err);
        } catch (IOException ex) {
            String err = "Failed to properly read CSRF Configuration file" +
                    ", exception=" + ex.getMessage();
            LOG.severe(err);
            throw new CSRFConfigException(err);
        } catch (SAXException ex) {
            String err = "Failed to parse CSRF Configuration file, exception=" + ex.getMessage();
            LOG.severe(err);
            throw new CSRFConfigException(err);
        }
    }

    /**
     * Loads logging properties if specified in the configuration file.
     *
     * @param element               DOM element to be read for the logging configuration file.
     * @throws SecurityException    if denied read access to the file.
     * @throws IOException          if there are problems reading from the file.
     */
    protected void loadLoggingConfiguration(Element element) throws SecurityException, IOException {
        String loggingConfigPath = readElementTextValue(element, Constants.JAVA_LOGGING_CONF);

        if (!loggingConfigPath.equals("")) {
            LOG.info("Custom Java logging configuration file specified");
            File loggingConfigFile = new File(loggingConfigPath);
            if (loggingConfigFile.exists()) {
                FileInputStream loggingConfigFS = new FileInputStream(loggingConfigFile);
                LogManager.getLogManager().readConfiguration(loggingConfigFS);
            } else {
                LOG.info("Error loading Java Logging Configuration file. " +
                        "Could not find the following the specified filename: " + loggingConfigFile);
            }

            csrfConfig.setProperty(Constants.JAVA_LOGGING_CONF, loggingConfigPath);
        }
    }


    /**
     * Parses document for configuration properties specifically used in HMAC based protection. These
     * properties include the key file, site wide timeout, user seed attribute name, and specific URLs.
     *
     * @param doc                   XML document to parse for HMAC properties.
     * @throws CSRFConfigException  if invalid attributes are specified in the configuration file.
     */
    protected void handleHMACConfigLoading(Document doc) throws CSRFConfigException {
        NodeList nl = doc.getElementsByTagName(Constants.CONF_HMACSETTINGS);
        Node node = nl.item(0);

        // Set some default values.
        csrfConfig.setProperty(Constants.CONF_HMAC_USERSEED_ATTR, Constants.CONF_DEFAULT_USERSEED_ATTR);
        csrfConfig.setProperty(Constants.CONF_HMAC_SITEWIDE_TIMEOUT, Constants.CONF_DEFAULT_TOKENTIMEOUT);

        if (node != null && node.getNodeType() == Node.ELEMENT_NODE) {
            // HMAC key file is a mandatory configuration setting.
            String hmacKeyfile = readElementTextValue((Element) node, Constants.CONF_HMAC_KEYFILE);
            setHMACKeyFile(hmacKeyfile);

            String seedAttributeName = readElementTextValue((Element) node, Constants.CONF_HMAC_USERSEED_ATTR);
            if (!seedAttributeName.equals("")) {
                csrfConfig.setProperty(Constants.CONF_HMAC_USERSEED_ATTR, seedAttributeName);
            }

            // Only set the timeout specified in the configuration file if it is valid.
            String sitewideTimeout = readElementTextValue((Element) node, Constants.CONF_HMAC_SITEWIDE_TIMEOUT);
            if (!CSRFConfigFileLoaderUtil.validateTimeout(sitewideTimeout, LOG)) {
                throw new CSRFConfigException("Invalid Sitewide timeout value submitted. SubmittedTimeout="
                        + sitewideTimeout);
            }

            if (!sitewideTimeout.equals("")) {
                csrfConfig.setProperty(Constants.CONF_HMAC_SITEWIDE_TIMEOUT, sitewideTimeout);
            }

            readXmlUrlListing((Element) node, Constants.CONF_URLSPECIFIC); // Read all specific URI properties.
        }
    }

    /**
     * Sets the HMAC signing key file. This file is required when using the HMAC protection mode.
     *
     * @param hmacKeyFile           path to the key file.
     * @throws CSRFConfigException  if no path is specified in the configuration file.
     */
    protected void setHMACKeyFile(String hmacKeyFile) throws CSRFConfigException {
        if (StringUtils.isBlank(hmacKeyFile)) {
            String err = "TOKEN_SIGNING-mode CSRF Protection requires Keyczar TOKEN_SIGNING File to " +
                    "be define within the configuration file";
            LOG.severe(err);
            throw new CSRFConfigException(err);
        }

        csrfConfig.setProperty(Constants.CONF_HMAC_KEYFILE, hmacKeyFile);
    }

    /**
     * Parses document for configuration properties specifically used in session based protection. These
     * properties include specific URLs, and one time use URLs, and the HTTP header.
     *
     * @param doc                   XML document to parse for HMAC properties.
     * @throws CSRFConfigException  if invalid attributes are specified in the configuration file.
     */
    protected void handleSessionConfigLoading(Document doc) throws CSRFConfigException {

        NodeList nl = doc.getElementsByTagName(Constants.CONF_SESSIONSETTINGS);
        Node node = nl.item(0);

        // Set some default values.
        csrfConfig.setProperty(Constants.CONF_SESSION_CSRF_HEADER, Constants.CONF_DEFAULT_CSRF_HEADER);

        if (node != null && node.getNodeType() == Node.ELEMENT_NODE) {

            String csrfHeader = readElementTextValue((Element) node, Constants.CONF_SESSION_CSRF_HEADER);
            if (!StringUtils.isBlank(csrfHeader)) {
                csrfConfig.setProperty(Constants.CONF_SESSION_CSRF_HEADER, csrfHeader);
            }

            readXmlUrlListing((Element) node, Constants.CONF_SESSION_ONETIMEUSE); // Read all one time URLs.
            readXmlUrlListing((Element) node, Constants.CONF_URLSPECIFIC); // Read all specific URLs.
        }
    }

    /**
     * Reads text value from the node with the specified element name. Returns empty string if node could not be read.
     *
     * @param element       document element with nodes.
     * @param elementName   element name used to find node to read text value of.
     * @return              Value read from node with element name, or empty string if node could not be read.
     */
    protected String readElementTextValue(Element element, String elementName) {
        if (element != null) {
            try {
                return element.getElementsByTagName(elementName).item(0).getFirstChild().getNodeValue();
            } catch (NullPointerException ex) {
                LOG.warning("Element for " + elementName + " is NULL.");
                return "";
            }
        } else
            return "";
    }

    /**
     * Reads attribute value from the node with the specified element name and attribute name. Returns empty string if
     * if node could not be read.
     *
     * @param element           document element with nodes.
     * @param elementName       element name used to find node.
     * @param attributeName     attribute name to find in node and read value of.
     * @return                  Value read from attribute of node with element name, or empty string if node could
     *                          not be read.
     */
    protected String readElementAttributeTextValue(Element element, String elementName, String attributeName) {
        if (element != null) {
            try {
                Node node = element.getElementsByTagName(elementName).item(0);
                return node.getAttributes().getNamedItem(attributeName).getFirstChild().getNodeValue();
            } catch (NullPointerException ex) {
                LOG.warning("Element for " + elementName + " is NULL.");
                return "";
            }
        } else
            return "";
    }

    /**
     * Reads URL values from all nodes with the specified list name. Returns empty string if node could
     * not be read. In case of the HMAC mode, also reads the timeout values.
     *
     * @param element               document element with nodes.
     * @param listName              list name used to find nodes.
     * @throws CSRFConfigException  if invalid attributes are specified for URLs.
     */
    protected void readXmlUrlListing(Element element, String listName)
            throws CSRFConfigException {
        NodeList nl = element.getElementsByTagName(listName);   // Get all nodes with specified list name.
        if (nl.getLength() > 0) {
            Element urlSpecificElement = (Element) nl.item(0);

            NodeList urlNodelist = urlSpecificElement.getElementsByTagName("url");

            // For every URL, get its name and any timeout value specified in HMAC configuration.
            for (int i = 0; i < urlNodelist.getLength(); i++) {
                Node urlNode = urlNodelist.item(i);
                String timeout = null;
                // URL validation can throw a CSRFConfigException that is not caught here. If we caught it, we would re-throw it anyway.
                if(urlNode.getFirstChild() != null) {
                    String urlExpression = CSRFConfigFileLoaderUtil.getValidatedUrl(urlNode.getFirstChild().getNodeValue());

                    if (CSRFConfigFileLoaderUtil.isHmacMode(csrfConfig)) {
                        try {
                            timeout = urlNode.getAttributes().getNamedItem("timeout").getFirstChild().getNodeValue();
                            if (!CSRFConfigFileLoaderUtil.validateTimeout(timeout, LOG)) {
                                throw new CSRFConfigException("Invalid URL Specific timeout value specified. URL="
                                        + urlExpression + ", EnteredTimeout=" + timeout);
                            }
                        } catch (NullPointerException ex) {
                            // If no timeout was set, we use the site wide value.
                            timeout = getProp(Constants.CONF_HMAC_SITEWIDE_TIMEOUT);
                        }
                    }

                    // One time use and URL specific URLs are mutually exclusive. Ignore URLs configured as both.
                    if (listName.equals("urlspecific")) {
                        if (CSRFConfigFileLoaderUtil.isSessionMode(csrfConfig) && oneTimeUseConfig.containsKey(urlExpression)) {
                            LOG.info("Not setting URL as URL Specific because has already been set as a OneTimeUse URL. url=" + urlExpression);
                            continue;
                        }

                        urlSpecificConfig.add(new SimpleImmutableEntry<String, Long>(urlExpression, timeout == null ? null : Long.parseLong(timeout)));
                    } else if (listName.equals("onetimeuse")) {
                        oneTimeUseConfig.put(urlExpression, Integer.valueOf(0));
                        urlSpecificConfig.add(new SimpleImmutableEntry<String, Long>(urlExpression, 0L));
                    } else if (listName.equals("exempt_urls")) {
                        exemptUrls.add(urlExpression);
                    }
                }
            }
        }
    }


    /**
     * Logs all of the properties loaded from the configuration file.
     */
    private void printConfiguration() {
        StringBuffer str = new StringBuffer("\n============\nAntiCSRF Configuration\n============\n");
        str.append(Constants.CONF_MODE + ": " + csrfConfig.getProperty(Constants.CONF_MODE) + "\n");
        str.append(Constants.CONF_TOKEN_REQATTR + ": " + csrfConfig.getProperty(Constants.CONF_TOKEN_REQATTR) + "\n");
        str.append(Constants.CONF_TOKEN_PARAM + ": " + csrfConfig.getProperty(Constants.CONF_TOKEN_PARAM) + "\n");
        str.append(Constants.CONF_ERROR + ": " + csrfConfig.getProperty(Constants.CONF_ERROR) + "\n");
        str.append(Constants.CONF_ERRORVAL + ": " + csrfConfig.getProperty(Constants.CONF_ERRORVAL) + "\n");
        str.append(Constants.JAVA_LOGGING_CONF + ": " + csrfConfig.getProperty(Constants.JAVA_LOGGING_CONF) + "\n");
        str.append(Constants.CONF_MONITORMODE + ": " + csrfConfig.getProperty(Constants.CONF_MONITORMODE) + "\n");

        str.append("\n-Exempt URLs-\n");

        for (String url : exemptUrls) {
            str.append("url: " + url + "\n");
        }

        if (CSRFConfigFileLoaderUtil.isHmacMode(csrfConfig)) {
            str.append("\n++TOKEN_SIGNING Protection Mode Settings++\n");
            str.append(Constants.CONF_HMAC_KEYFILE + ": " + csrfConfig.getProperty(Constants.CONF_HMAC_KEYFILE) + "\n");
            str.append(Constants.CONF_HMAC_SITEWIDE_TIMEOUT + ": " + csrfConfig.getProperty(Constants.CONF_HMAC_SITEWIDE_TIMEOUT) + "\n");
            str.append(Constants.CONF_HMAC_USERSEED_ATTR + ": " + csrfConfig.getProperty(Constants.CONF_HMAC_USERSEED_ATTR) + "\n");

            str.append("\n--URL Specific Configuration--\n");
            for (Map.Entry<String, Long> urlEntry : urlSpecificConfig) {
                str.append("url: " + urlEntry.getKey() + "   timeout: " + urlEntry.getValue() + "\n");
            }
        } else if (CSRFConfigFileLoaderUtil.isSessionMode(csrfConfig)) {
            str.append("\n++Session Protection Mode Settings++\n");
            str.append(Constants.CONF_SESSION_CSRF_HEADER + ": " + csrfConfig.getProperty(Constants.CONF_SESSION_CSRF_HEADER) + "\n");
            str.append("\n--URL Specific Configuration--\n");
            for (Map.Entry<String, Long> urlEntry : urlSpecificConfig) {
                str.append("url: " + urlEntry.getKey() + "\n");
            }

            str.append("\n--One Time Use Configuration--\n");
            for (String url : oneTimeUseConfig.keySet()) {
                str.append("url: " + url + "\n");
            }
        }
        LOG.info(str.toString());

    }

    /**
     * Gets a value specified in the configuration file for the specified configuration property. Returns default property
     * if it could not be found in the configuration file.
     *
     * @param configProperty    property used in configuration file that maps to value.
     * @return                  Value specified in the configuration value using specified configuration property, or the
     *                          default value if it could not be found.
     */
    private String getProp(String configProperty) {
        try {
            return csrfConfig.getProperty(configProperty);
        } catch (Exception e) {
            LOG.warning("Failed to find property: " + configProperty + " exmsg= " + e.getMessage());
            return Constants.defaultConfigs.get(configProperty);
        }
    }

    /**
     * Gets a list of URLs that that will have a unique token, valid only for that URL, as specified in the configuration file.
     *
     * @return  List of URLs specified in the configuration file that require unique tokens.
     */
    private List<Map.Entry<String, Long>> getUrlSpecificRuleEntries() {
        return urlSpecificConfig;
    }

    /**
     * Gets a list of URLs that will be marked as exempt from token validation, as specified in the configuration file.
     *
     * @return  List of exempt URLs specified in the configuration file.
     */
    private List<String> getExemptUrlEntries() {
        return exemptUrls;
    }

    /**
     * Loads the configuration file and builds the CSRF config object. Sets the token recollection strategy to determine
     * the protection strategy.
     *
     * @param configFilename    path name to the configuration file.
     * @return                  Config object containing all properties parsed from the configuration file and names of
     *                          default factory classes.
     */
    static CSRFConfig loadConfig(String configFilename) {
        CSRFConfigFileLoader loader = new CSRFConfigFileLoader(configFilename);

        CSRFTokenRecollectionStrategy tokenRecollectionStrategy = null;

        if (CSRFConfigFileLoaderUtil.isHmacMode(loader.csrfConfig)) {
            tokenRecollectionStrategy = CSRFTokenRecollectionStrategy.TOKEN_SIGNING;
        } else if (CSRFConfigFileLoaderUtil.isSessionMode(loader.csrfConfig)) {
            tokenRecollectionStrategy = CSRFTokenRecollectionStrategy.TOKEN_STORAGE;
        }
        // Default strategy is session based.
        tokenRecollectionStrategy = tokenRecollectionStrategy != null ?
                tokenRecollectionStrategy
                : CSRFTokenRecollectionStrategy.TOKEN_STORAGE;

        Map<String, String> customConfigs = new HashMap<String, String>();

        for (String property : loader.csrfConfig.stringPropertyNames()) {
            customConfigs.put(property, loader.csrfConfig.getProperty(property));
        }

        return CSRFConfig.builder()
                .setCSRFRulesServiceFactoryClass(loader.getProp(Constants.CONF_RULES_MANAGER_FACTORY_CLASS))
                .setCSRFTokenServiceFactoryClass(loader.getProp(Constants.CONF_PROTECTION_SERVICE_FACTORY_CLASS))
                .setDefaultTokenTimeout(NumberUtils.createLong(loader.getProp(Constants.CONF_DEFAULT_TOKENTIMEOUT)))
                .setEncryptionKeyPath(loader.getProp(Constants.CONF_HMAC_KEYFILE))
                .setTokenRecollectionStrategy(tokenRecollectionStrategy.name())
                .setTokenParameterName(loader.getProp(Constants.CONF_TOKEN_PARAM))
                .setRequestAttributeName(loader.getProp(Constants.CONF_TOKEN_REQATTR))
                .setSessionCSRFHeader(loader.getProp(Constants.CONF_SESSION_CSRF_HEADER))
                .addProtectionRules(loader.getUrlSpecificRuleEntries())
                .addExemptionRules(loader.getExemptUrlEntries())
                .setCustomConfigValues(customConfigs)
                .build();
    }
}
