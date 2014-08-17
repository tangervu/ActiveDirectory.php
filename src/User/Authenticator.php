<?php
/**
 * Template for authenticating the user
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 * @license http://opensource.org/licenses/LGPL-3.0 LGPL v3
 */

namespace ActiveDirectory\User;

interface Authenticator {
	
	/**
	 * Try to identify the user
	 * 
	 * @returns user login if successful (string)
	 * @throw AuthenticatorException login failed
	 */
	public function identify();
}
