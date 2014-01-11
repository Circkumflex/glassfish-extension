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

import java.nio.charset.CharacterCodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Level;
//import com.sun.enterprise.connectors.ConnectorRuntime;
import com.sun.appserv.connectors.internal.api.ConnectorRuntime;

import com.sun.enterprise.universal.GFBase64Encoder;

import com.sun.enterprise.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.common.Util;
import com.sun.enterprise.util.Utility;

import java.util.Arrays;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.xml.bind.DatatypeConverter;

import org.glassfish.hk2.api.ActiveDescriptor;
import org.glassfish.hk2.utilities.BuilderHelper;

/**
 * @author Oleg Tsarev <tsarev.oi@mail.ru>
 * 
 */
public final class BasicSecuredRestRealm extends RestRealm {
    // Descriptive string of the authentication type of this realm.

    public static final String AUTH_TYPE = "digest";
    public static final String PARAM_DIGEST_ALGORITHM = "digest-algorithm";
    public static final String NONE = "none";
    public static final String PARAM_ENCODING = "encoding";
    public static final String HEX = "hex";
    public static final String BASE64 = "base64";
    public static final String PARAM_CHARSET = "charset";
    public static final String PARAM_SERVICE_URI = "service-uri";
    
    private static final char[] HEXADECIMAL = {'0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    
    private String serviceURI = null;
    private Map<String, Vector> groupCache;
    private Vector<String> emptyVector;
    private Map<String, AuthenticationDescriptor> modelCache;
    private MessageDigest md = null;
    private ActiveDescriptor<ConnectorRuntime> cr;

    /**
     * Initialize a realm with some properties. This can be used when
     * instantiating realms from their descriptions. This method may only be
     * called a single time.
     *
     * @param props Initialization parameters used by this realm.
     * @exception BadRealmException If the configuration parameters identify a
     * corrupt realm.
     * @exception NoSuchRealmException If the configuration parameters specify a
     * realm which doesn't exist.
     */
    @SuppressWarnings("unchecked")
    public synchronized void init(Properties props)
            throws BadRealmException, NoSuchRealmException {
        super.init(props);
        String jaasCtx = props.getProperty(IASRealm.JAAS_CONTEXT_PARAM);

        String digestAlgorithm = props.getProperty(PARAM_DIGEST_ALGORITHM,
                getDefaultDigestAlgorithm());
        String encoding = props.getProperty(PARAM_ENCODING, NONE);
        String charset = props.getProperty(PARAM_CHARSET, "UTF-8");
        serviceURI = props.getProperty(PARAM_SERVICE_URI);
        
        cr = (ActiveDescriptor<ConnectorRuntime>) Util.getDefaultHabitat().getBestDescriptor(BuilderHelper.createContractFilter(ConnectorRuntime.class.getName()));

        if (jaasCtx == null) {
            String msg = sm.getString(
                    "realm.missingprop", IASRealm.JAAS_CONTEXT_PARAM, "RestRealm");
            throw new BadRealmException(msg);
        }

        
        if (serviceURI == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_SERVICE_URI, "RestRealm");
            throw new BadRealmException(msg);
        }

        if (!NONE.equalsIgnoreCase(digestAlgorithm)) {
            try {
                md = MessageDigest.getInstance(digestAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                String msg = sm.getString("restrealm.notsupportdigestalg",
                        digestAlgorithm);
                throw new BadRealmException(msg);
            }
        }

        this.setProperty(IASRealm.JAAS_CONTEXT_PARAM, jaasCtx);
        
        this.setProperty(PARAM_DIGEST_ALGORITHM, digestAlgorithm);
        if (encoding != null) {
            this.setProperty(PARAM_ENCODING, encoding);
        }
        if (charset != null) {
            this.setProperty(PARAM_CHARSET, charset);
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest("RealmRealm : "
                    + IASRealm.JAAS_CONTEXT_PARAM + "= " + jaasCtx + ", "
                    + PARAM_SERVICE_URI + "= " + serviceURI + ", "
                    + PARAM_DIGEST_ALGORITHM + " = " + digestAlgorithm + ", "
                    + PARAM_ENCODING + " = " + encoding + ", "
                    + PARAM_CHARSET + " = " + charset);
        }
        
        groupCache = new HashMap<String, Vector>();
        emptyVector = new Vector<String>();
        modelCache = new HashMap<String, AuthenticationDescriptor>();
    }

    /**
     * Returns a short (preferably less than fifteen characters) description of
     * the kind of authentication which is supported by this realm.
     *
     * @return Description of the kind of authentication that is directly
     * supported by this realm.
     */
    public String getAuthType() {
        return AUTH_TYPE;
    }
    
    /**
     * Returns the name of all the groups that this user belongs to. It loads
     * the result from groupCache first. This is called from web path group
     * verification, though it should not be.
     *
     * @param username Name of the user in this realm whose group listing is
     * needed.
     * @return Enumeration of group names (strings).
     * @exception InvalidOperationException thrown if the realm does not support
     * this operation - e.g. Certificate realm does not support this operation.
     */
    public Enumeration getGroupNames(String username)
            throws InvalidOperationException, NoSuchUserException {
        Vector vector = groupCache.get(username);
        return vector.elements();
    }

    private void setGroupNames(String username, String[] groups) {
        Vector<String> v = null;

        if (groups == null) {
            v = emptyVector;

        } else {
            v = new Vector<String>(groups.length + 1);
            for (int i = 0; i < groups.length; i++) {
                v.add(groups[i]);
            }
        }

        synchronized (this) {
            groupCache.put(username, v);
        }
    }

    /**
     * Request rest service
     *
     * @param login Any user identity
     * @return real user identity
     */
    private AuthenticationDescriptor getAuthenticationModel(String login, char[] password) {
        String hash = login + ":" + new String(password);
        
        if (modelCache.containsKey(hash)) {
            AuthenticationDescriptor cachedModel = modelCache.get(hash);
            if (cachedModel != null) {
                return cachedModel;
            }
        }
        
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(serviceURI);
        try {

            AuthenticationDescriptor model = target
                    .request()
                    .header("Authorization", "Basic " + DatatypeConverter.printBase64Binary(hash.getBytes(this.getProperty(PARAM_CHARSET))))
                    .get(AuthenticationDescriptor.class);
            
            synchronized (this) {
                modelCache.put(hash, model);
            }
            
            setGroupNames(model.getName(), model.getGroups());
            
            return model;
        } catch (Exception ex) {
            _logger.log(Level.SEVERE, "restrealm.invaliduser", login);
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot validate user", ex);
            }
        } finally {
            client.close();
        }
        return null;
    }

    /**
     * Invoke the native authentication call.
     *
     * @param username User to authenticate.
     * @param password Given password.
     * @returns list of groups
     */
    public AuthenticationDescriptor authenticate(String username, char[] password) {
        AuthenticationDescriptor model = getAuthenticationModel(username, password);
        String[] groups = null;
        if (isUserValid(model, password)) {
            groups = addAssignGroups(model.getGroups());
            setGroupNames(username, groups);
            model.setGroups(groups);
        }
        return model;
    }
 
    /**
     * Test if a user is valid
     *
     * @param model user's authentication model
     * @param password user's password
     * @return true if valid
     */
    private boolean isUserValid(AuthenticationDescriptor model, char[] password) {

        boolean valid = false;

        try {
            char[] hpwd = hashPassword(password);
            
            if (model != null) {
                
                char[] passwd = model.getPassword().toCharArray();
                
                if (HEX.equalsIgnoreCase(getProperty(PARAM_ENCODING))) {
                    valid = true;
                    //Do a case-insensitive equals
                    if (hpwd.length == passwd.length) {
                        for (int i = 0; i < hpwd.length; i++) {
                            if (!(Character.toLowerCase(passwd[i]) == Character.toLowerCase(hpwd[i]))) {
                                valid = false;
                                break;
                            }
                        }
                    } else {
                        valid = false;
                    }
                } else {
                    valid = Arrays.equals(passwd, hpwd);
                }
            }
        } catch (Exception ex) {
            _logger.log(Level.SEVERE, "restrealm.invaliduser", model.getName());
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot validate user", ex);
            }
        } 
        return valid;
    }

    private char[] hashPassword(char[] password)
            throws CharacterCodingException {
        byte[] bytes = null;
        char[] result = null;
        String charSet = getProperty(PARAM_CHARSET);
        bytes = Utility.convertCharArrayToByteArray(password, charSet);

        if (md != null) {
            synchronized (md) {
                md.reset();
                bytes = md.digest(bytes);
            }
        }

        String encoding = getProperty(PARAM_ENCODING);
        if (HEX.equalsIgnoreCase(encoding)) {
            result = hexEncode(bytes);
        } else if (BASE64.equalsIgnoreCase(encoding)) {
            result = base64Encode(bytes).toCharArray();
        } else { // no encoding specified
            result = Utility.convertByteArrayToCharArray(bytes, charSet);
        }
        return result;
    }

    private char[] hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(2 * bytes.length);
        for (int i = 0; i < bytes.length; i++) {
            int low = (int) (bytes[i] & 0x0f);
            int high = (int) ((bytes[i] & 0xf0) >> 4);
            sb.append(HEXADECIMAL[high]);
            sb.append(HEXADECIMAL[low]);
        }
        char[] result = new char[sb.length()];
        sb.getChars(0, sb.length(), result, 0);
        return result;
    }

    private String base64Encode(byte[] bytes) {
        GFBase64Encoder encoder = new GFBase64Encoder();
        return encoder.encode(bytes);
    }

}
