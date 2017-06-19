/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sid.localos;

/**
 *
 * @author sidde
 */

import java.security.acl.Group;
import javax.security.auth.login.LoginException;
import net.sf.jpam.Pam;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;
import org.jboss.logging.Logger;
import org.jboss.security.SimpleGroup;

public class LoginLx extends UsernamePasswordLoginModule {
     protected static Logger log = Logger.getLogger(LoginLx.class);
     private SimplePrincipal user;
     private boolean guestOnly;

    protected boolean validatePassword(String password, String username) {
         boolean isValid = false;
         if (password == null) {
             this.guestOnly = true;
             isValid = true;
             this.user = new SimplePrincipal("guest");
         } else {
             isValid = this.isValidUser(username, password);
         }
         return isValid;
     }

    public boolean isValidUser(String username, String password) {
         try {
             Pam pam = new Pam();
             System.out.println("Pam created " + (Object)pam);
             boolean authenticated = pam.authenticateSuccessful(username, password);
             if (authenticated) {
                 log.info("Authentication Result: " + authenticated);
                 log.info("Authentication is successful with user: "+username);
                 return true;
             }
         }
         catch (LinkageError e) {
             log.info("Please check PAM library is setup properly");
             e.printStackTrace();
         }
         return false;
     }

    protected String getUsersPassword() throws LoginException {
         return this.getUsername();
     }

    @Override
    protected Group[] getRoleSets() throws LoginException {
        Group[] roleSets = {new SimpleGroup("Roles")};
	   if(!guestOnly){
			roleSets[0].addMember(new SimplePrincipal("JbossAdmin"));
		}else{
			roleSets[0].addMember(new SimplePrincipal("guest"));
		}
	   return roleSets;
    }
 }
