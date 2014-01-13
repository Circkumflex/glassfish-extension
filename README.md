Glassfish-extension library
===================

Specific extension for Glassfish 4. Currently contains:
* MultipleLoginModule which implements logic of multiple login for single principle. For instance: id, login, email.
* FieldBasedJDBCRealm and QueryBasedJDBCRealm implementations dependent on MultipleLoginModule.
* RestLoginModule which implements logic of requesting for third side service.
* BasicSecuredRestRealm implementation dependent on RestLoginModule. Specially implemented for third side services secured with basic authentication.
* AuthenticationDescriptor - model, which third side service should return as a JSON string.

Using of library
================

* Add library jar files to server libraries. _IMPORTANT!_ For example: ../domain1/lib. Do not push it to subfolders of ../domain1/lib.
* Configure realm in Glassfish (in case of exception at Admin console do it manually in domain.xml).
* Configure application to use previously configured realm.

FieldsBasedJDBCRealm
====================

FieldsBasedJDBCRealm based on JDBCRealm of Glassfish server, but extends it for support multiple login field (for example: username and email).This realm has all possibilities of basic JDBCRealm, but also it provides new property _'user-columns'_, which accept names of all login fields separated with ",".

Configuring:
* Set the name of realm
* Choose class of realm: __com.glassfish.extension.auth.realm.jdbc.FieldsBasedJDBCRealm__
* Add next properties with the following values for field based realm:
```
jaas-context:<realm, context name>
password-column:<name of password field>
datasource-jndi:<jndi name>
group-table:<name of group table>
user-table:<name of user table>
group-name-column:<name of group id field>
group-table-user-name-column:<name of user field of group table>
digest-algorithm:none
user-name-column:<name of user id field>
user-columns:<names of all user login fields separated with ",">
```

* Add LoginModule mapping to login.conf:
```
<realm, context name> {
    com.glassfish.extension.auth.login.MultipleLoginModule required;
};
```

* Restart server and check domain.xml, it should contains following block for field based realm:
```xml
<auth-realm name="<realm, context name>" classname="com.glassfish.extension.auth.realm.FieldsBasedJDBCRealm">
    <property name="jaas-context" value="<realm, context name>"></property>
    <property name="password-column" value="<name od password column>"></property>
    <property name="datasource-jndi" value="<jndi name>"></property>
    <property name="group-table" value="<name of group table>"></property>
    <property name="user-table" value="<name of user table>"></property>
    <property name="group-name-column" value="<name of group id column>"></property>
    <property name="group-table-user-name-column" value="<name of user column of group table>"></property>
    <property name="digest-algorithm" value="none"></property>
    <property name="user-name-column" value="<name of user id column>"></property>
    <property name="user-columns" value="<names of all user login columns separated with ','>"></property>
</auth-realm>
```

QueryBasedJDBCRealm
===================

QueryBasedJDBCRealm based on JDBCRealm of Glassfish server, but it was rewrote for support more flexible configuration. This realm accept just three SQL-queries for:
* selecting actual id of user (it also allows to have multiple login fields)
* selecting password of user
* selecting groups of user
It needs to know SQL basics, but it's much easier to use.

Configuring:
* Set the name of realm
* Choose class of realm: __com.glassfish.extension.auth.realm.jdbc.QueryBasedJDBCRealm__
* Add next properties with the following values for query based realm:
```
jaas-context:<realm, context name>
datasource-jndi:<jndi name>
user-query:SELECT <name of user id field> FROM <name of user table> WHERE <name of one of login fields> = ? OR <name of another login firld> = ? OR ...
password-query:SELECT <name of password field> FROM <name of user table> WHERE <name of user id field> = ?
group-query:SELECT <name of group id field> FROM <name of group table> WHERE <name of user id field of group table> = ?
digest-algorithm:none
```

* Add LoginModule mapping to login.conf:
```
<realm, context name> {
    com.glassfish.extension.auth.login.MultipleLoginModule required;
};
```

* Restart server and check domain.xml, it should contains following block for query based realm:
```xml
<auth-realm name="<realm, context name>" classname="com.glassfish.extension.auth.realm.jdbc.QueryBasedJDBCRealm">
    <property name="jaas-context" value="<realm, context name>"></property>
    <property name="datasource-jndi" value="<jndi name>"></property>
    <property name="user-query" value="SELECT <name of user id field> FROM <name of user table> WHERE <name of one of login fields> = ? OR <name of another login field> = ? OR ..."></property>
    <property name="password-query" value="SELECT <name of password field> FROM <name of user table> WHERE <name of user id field> = ?"></property>
    <property name="group-query" value="SELECT <name of group id field> FROM <name of group table> WHERE <name of user id field of group table> = ?"></property>
    <property name="digest-algorithm" value="none"></property>
</auth-realm>
```

BasicSecuredRestRealm
=====================

BasicSecuredRestRealm allows to use BASIC-secured third-part service to authenticate user. During authentication it requests remote service, which should return JSON string as a result of converting of __AuthenticationDescriptor__.

Configuring:
* Set the name of realm
* Choose class of realm: __com.glassfish.extension.auth.realm.rest.BasicSecuredRestRealm__
* Add next properties with the following values for realm:
```
jaas-context:<realm, context name>
service-uri:<url of authentication service, for example:http://localhost:8080/your-services/auth>
digest-algorithm:none
```

* Add LoginModule mapping to login.conf:
```
<realm, context name> {
	com.glassfish.extension.auth.login.RestLoginModule required;
};
```

* Restart server and check domain.xml, it should contains following block for realm:
```xml
<auth-realm name="<realm, context name>" classname="com.glassfish.extension.auth.realm.rest.BasicSecuredRestRealm">
    <property name="jaas-context" value="<realm, context name>"></property>
    <property name="service-uri" value="<url of authentication service, for example:http://localhost:8080/your-services/auth>"></property>
    <property name="digest-algorithm" value="none"></property>
</auth-realm>
```

Configuring of application
==========================

Check that your application work with <realm, context name> or contains
special mapping to this name.
```xml
<login-config>
    <auth-method>BASIC</auth-method>
    <realm-name><realm, context name></realm-name>
</login-config>
```