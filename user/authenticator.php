<?php
/**
 * Template for authenticating the user
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 */

namespace User {
	interface Authenticator {
		
		/**
		 * Try to identify the user
		 * 
		 * @returns user login if successful (string)
		 * @throw AuthenticatorException login failed
		 */
		public function identify();
	}
	
	class AuthenticatorException extends \Exception { }
}
