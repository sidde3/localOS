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
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;
import org.jboss.logging.Logger;
import org.jboss.security.SimpleGroup;

public class loginW extends UsernamePasswordLoginModule {
    protected static Logger log = Logger.getLogger(loginW.class);
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
        WindowsAuthProviderImpl authenticationlevel = new WindowsAuthProviderImpl();
        IWindowsIdentity loggedOnUser = authenticationlevel.logonUser(username, password);
        if (!loggedOnUser.isGuest()) {
            log.info("Authentication Successful with user: "+username);
            return true;
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
