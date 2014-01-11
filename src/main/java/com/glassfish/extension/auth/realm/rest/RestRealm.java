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
package com.glassfish.extension.auth.realm.rest;

import com.sun.appserv.security.AppservRealm;

/**
 * @author Oleg Tsarev <tsarev.oi@mail.ru>
 * 
 */
public abstract class RestRealm extends AppservRealm {
    
    public abstract AuthenticationDescriptor authenticate(String username, char[] password);
   
}
