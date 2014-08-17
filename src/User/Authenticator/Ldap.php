<?php
/**
 * Authenticator using LDAP (ActiceDirectory) server as a backend
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 * @license http://opensource.org/licenses/LGPL-3.0 LGPL v3
 */

namespace ActiveDirectory\User\Authenticator;

class Ldap implements \ActiveDirectory\User\Authenticator {
	
	protected $ad;
	
	public $realm = 'Password protected site';
	
	/**
	 * Define the LDAP server attributes
	 */
	public function __construct(\ActiveDirectory\ActiveDirectory $ad) {
		$this->ad = $ad;
	}
	
	public function identify() {
		
		//User has entered username & password
		if(isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
			//Verify the username on the AD server
			if($this->ad->authenticate($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
				return $_SERVER['PHP_AUTH_USER'];
			}
		}
		
		//No login info provided or login failed, asking for username and password
		header('WWW-Authenticate: Basic realm="' . $this->realm . '"',true,401);
		
		//Display authentication information from a template html
		include dirname(__FILE__) . '/../../../templates/login.php';
		exit;
	}
}
