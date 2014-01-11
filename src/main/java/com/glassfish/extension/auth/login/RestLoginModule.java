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

import com.glassfish.extension.auth.realm.rest.AuthenticationDescriptor;
import com.glassfish.extension.auth.realm.rest.RestRealm;
import com.sun.appserv.security.AppservPasswordLoginModule;
import com.sun.enterprise.security.auth.login.common.LoginException;
import java.util.Arrays;
import java.util.logging.Level;

/**
 * @author Oleg Tsarev <tsarev.oi@mail.ru>
 * 
 */
public class RestLoginModule extends AppservPasswordLoginModule {
    /**
     * Perform REST authentication.
     *
     * @throws LoginException If login fails (JAAS login() behavior).
     */    
    protected void authenticateUser() throws LoginException {
        if (!(_currentRealm instanceof RestRealm)) {
            String msg = sm.getString("restlm.badrealm");
            throw new LoginException(msg);
        }
        
        final RestRealm restRealm = (RestRealm)_currentRealm;

        // A JDBC user must have a name not null and non-empty.
        if ( (_username == null) || (_username.length() == 0) ) {
            String msg = sm.getString("restlm.nulluser");
            throw new LoginException(msg);
        }
        
        AuthenticationDescriptor model = restRealm.authenticate(_username.toLowerCase(), getPasswordChar());
        
        _username =  model.getName();
        String[] grpList = model.getGroups();

        if (grpList == null) {  // JAAS behavior
            String msg = sm.getString("restlm.loginfail", _username);
            throw new LoginException(msg);
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.log(Level.FINEST, "REST login succeeded for: {0} groups:{1}",
                new Object[]{_username, Arrays.toString(grpList)});
        }
        
        commitUserAuthentication(grpList);
        
    }

}
