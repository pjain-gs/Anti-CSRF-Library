
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

import org.apache.commons.lang3.StringUtils;

import java.util.Date;

/**
 * Token helper class containing methods utilized by token generation and validation methods.
 */
public class TokenHelper {

    private static final String TOKEN_FIELD_DELIMITER = ":";

    /**
     * Generates a plain token for the from the user seed, URL, and timeout value for signing services.
     *
     * @param url           URL for which to generate token.
     * @param userSeed      user seed correlating to authenticated user.
     * @param tokenTimeout  timeout value for token, if applicable.s
     * @return              Plain token with inputs concatenated by token field delimiter.
     */
    public static String generatePlainTokenString(String url, String userSeed, Long tokenTimeout) {
        //  Plain token form <user seed>:<url>:<timeout>
        StringBuilder plainToken = new StringBuilder();
        if (!StringUtils.isBlank(userSeed))
            plainToken.append(StringUtils.trimToEmpty(userSeed))
                    .append(TOKEN_FIELD_DELIMITER);
        if (!StringUtils.isBlank(url))
            plainToken.append(StringUtils.trimToEmpty(url))
                    .append(TOKEN_FIELD_DELIMITER);
        return plainToken.append(tokenTimeout != null ? String.valueOf(tokenTimeout) : "")
                .toString();

    }

    /**
     * Returns <code>true</code> if the token has expired.
     *
     * @param tokenCreationTime Time token was created.
     * @param tokenTimeout      Duration token is valid for.
     * @return                  <code>True</code> if the token has expired.
     * @throws RuntimeException if error occurred during token timestamp verification.
     */
    public static boolean timestampIsExpired(Long tokenCreationTime, Long tokenTimeout) {
        long currentTime = new Date().getTime();
        long elapsedTime = (currentTime - tokenCreationTime);

        return elapsedTime >= tokenTimeout;
    }

}
