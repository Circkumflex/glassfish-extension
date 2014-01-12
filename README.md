Glassfish-extension library
===================

Specific extension for Glassfish 4. Currently contains:
* MultipleLoginModule which implements logic of multiple login for single principle. For instance: id, login, email.
* FieldBasedJDBCRealm and QueryBasedJDBCRealm implementations dependent on MultipleLoginModule.
* RestLoginModule which implements logic of requesting for third side service.
* BasicSecuredRestRealm implementation dependent on RestLoginModule. Specially implemented for third side services secured with basic authentication.
* AuthenticationDescriptor - model, which third side service should return as a JSON string.

Using
=====

* Add library jar files to server libraries. IMPORTANT! For example: ../domain1/lib. Do not push it to subfolders of ../domain1/lib.
* Configure realm in Glassfish (in case of exception at Admin console do it manually in domain.xml).
* Configure application to use previously configured realm.

Using of FieldsBasedJDBCRealm
=============================

* Set the name of realm
* Choose class of realm: com.glassfish.extension.auth.realm.jdbc.FieldsBasedJDBCRealm
* Add next properties with the following values for field based realm:
`jaas-context:<realm, context name>
password-column:<name of password field>
datasource-jndi:<jndi name>
group-table:<name of group table>
user-table:<name of user table>
group-name-column:<name of group id field>
group-table-user-name-column:<name of user field of group table>
digest-algorithm:none
user-name-column:<name of user id field>
user-columns:<names of all user login fields separated with ",">`

* Add LoginModule mapping to login.conf:
`<realm, context name> {
	com.glassfish.extension.auth.login.MultipleLoginModule required;
};`

* Restart server and check domain.xml, it should contains following block for field based realm:
`<auth-realm name="<realm, context name>" classname="com.glassfish.extension.auth.realm.FieldsBasedJDBCRealm">
    <property name="jaas-context" value="<realm, context name>"></property>
    <property name="password-column" value="<name od password column>"></property>
    <property name="datasource-jndi" value="<jndi name>"></property>
    <property name="group-table" value="<name of group table>"></property>
    <property name="user-table" value="<name of user table>"></property>
    <property name="group-name-column" value="<name of group id column>"></property>
    <property name="group-table-user-name-column" value="<name of user column of group table>"></property>
    <property name="digest-algorithm" value="none"></property>
    <property name="user-name-column" value="<name of user id column>"></property>
    <property name="user-columns" value="<names of all user login columns separated with ",">"></property>
</auth-realm>`

Using of QueryBasedJDBCRealm
============================

* Set the name of realm
* Choose class of realm: com.glassfish.extension.auth.realm.jdbc.QueryBasedJDBCRealm
* Add next properties with the following values for query based realm:
`jaas-context:<realm, context name>
datasource-jndi:<jndi name>
user-query:SELECT <name of user id field> FROM <name of user table> WHERE <name of one of login fields> = ? OR <name of another login firld> = ? OR ...
password-query:SELECT <name of password field> FROM <name of user table> WHERE <name of user id field> = ?
group-query:SELECT <name of group id field> FROM <name of group table> WHERE <name of user id field of group table> = ?
digest-algorithm:none`

* Add LoginModule mapping to login.conf:
`<realm, context name> {
	com.glassfish.extension.auth.login.MultipleLoginModule required;
};`

* Restart server and check domain.xml, it should contains following block for query based realm:
`<auth-realm name="<realm, context name>" classname="com.glassfish.extension.auth.realm.jdbc.QueryBasedJDBCRealm">
    <property name="jaas-context" value="<realm, context name>"></property>
    <property name="datasource-jndi" value="<jndi name>"></property>
    <property name="user-query" value="SELECT <name of user id field> FROM <name of user table> WHERE <name of one of login fields> = ? OR <name of another login field> = ? OR ..."></property>
    <property name="password-query" value="SELECT <name of password field> FROM <name of user table> WHERE <name of user id field> = ?"></property>
    <property name="group-query" value="SELECT <name of group id field> FROM <name of group table> WHERE <name of user id field of group table> = ?"></property>
    <property name="digest-algorithm" value="none"></property>
</auth-realm>`

Configuring of application
==========================

Check that your application work with <realm, context name> or contains
special mapping to this name.
<login-config>
    <auth-method>BASIC</auth-method>
    <realm-name><realm, context name></realm-name>
</login-config>

