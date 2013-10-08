<?php
/**
 * Authenticator using HTTP servers internal authentication
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 * @license http://opensource.org/licenses/LGPL-3.0 LGPL v3
 */

namespace User\Authenticator {
	
	require_once dirname(__FILE__) . '/../authenticator.php';
	
	class Http implements \User\Authenticator {
		
		public function identify() {
			//Web server has identified the user
			if(isset($_SERVER['REMOTE_USER']) && $_SERVER['REMOTE_USER'] != '') {
				return $_SERVER['REMOTE_USER'];
			}
			
			//Web server has identified the user, using php-cgi
			else if(isset($_SERVER['REDIRECT_REMOTE_USER']) && $_SERVER['REDIRECT_REMOTE_USER']) {
				return $_SERVER['REDIRECT_REMOTE_USER'];
			}
			
			//Could not identify the user
			else {
				throw new \User\AuthenticatorException("Not able to identify the user using HTTP server features");
			}
		}
	}
}
