/*
 * This file is part of ***  M y C o R e  ***
 * See http://www.mycore.de/ for details.
 *
 * MyCoRe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MyCoRe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MyCoRe.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.mycore.tools.restapi.client.v1;

/**
 * MyCoRe REST-API Credentials
 * 
 * @author Robert Stephan
 *
 */
public class MyCoReRestAPICredentials {

    private String restAPIBaseURL;
    private String user;
    private String password;

    public MyCoReRestAPICredentials(String restAPIBaseURL, String user, String password) {
        super();
        setRestAPIBaseURL(restAPIBaseURL);
        setUser(user);
        setPassword(password);
    }

    public String getRestAPIBaseURL() {
        return restAPIBaseURL;
    }

    public void setRestAPIBaseURL(String restAPIBaseURL) {
        this.restAPIBaseURL = restAPIBaseURL;
        if (this.restAPIBaseURL.endsWith("/")) {
            setRestAPIBaseURL(this.restAPIBaseURL.substring(0, this.restAPIBaseURL.length() - 1));
        }
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
