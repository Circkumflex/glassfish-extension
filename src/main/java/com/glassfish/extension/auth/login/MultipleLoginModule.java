/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * This file is part of glassfish-extension library.
 * Copyright (C) 2012  Oleg Tsarev
 * 
 * Glassfish-extension is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 */
package com.glassfish.extension.auth.login;

import com.glassfish.extension.auth.realm.jdbc.MultipleLoginRealm;
import com.sun.appserv.security.AppservPasswordLoginModule;
import com.sun.enterprise.security.auth.login.common.LoginException;
import java.util.Arrays;
import java.util.logging.Level;

/**
 * @author Oleg Tsarev <tsarev.oi@mail.ru>
 * 
 */
public class MultipleLoginModule extends AppservPasswordLoginModule {
    /**
     * Perform JDBC authentication.
     *
     * @throws LoginException If login fails (JAAS login() behavior).
     */    
    protected void authenticateUser() throws LoginException {
        if (!(_currentRealm instanceof MultipleLoginRealm)) {
            String msg = sm.getString("jdbclm.badrealm");
            throw new LoginException(msg);
        }
        
        final MultipleLoginRealm jdbcRealm = (MultipleLoginRealm)_currentRealm;

        // A JDBC user must have a name not null and non-empty.
        if ( (_username == null) || (_username.length() == 0) ) {
            String msg = sm.getString("jdbclm.nulluser");
            throw new LoginException(msg);
        }

        _username = jdbcRealm.getActualLogin(_username.toLowerCase());
        
        String[] grpList = jdbcRealm.authenticate(_username, getPasswordChar());

        if (grpList == null) {  // JAAS behavior
            String msg = sm.getString("jdbclm.loginfail", _username);
            throw new LoginException(msg);
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.log(Level.FINEST, "JDBC login succeeded for: {0} groups:{1}",
                new Object[]{_username, Arrays.toString(grpList)});
        }
        
        commitUserAuthentication(grpList);
    }

}
