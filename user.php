<?php
/**
 * Get user information
 * 
 *
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 **/

require_once dirname(__FILE__) . '/user/authenticator.php';

class User {
	
	protected $authenticators = array();
	protected $login;
	protected $authenticated = false;
	
	public function __construct() {
		//Primary authentication method: rely on web servers user authentication
		require_once dirname(__FILE__) . '/user/authenticator/http.php';
		$authenticator = new User\Authenticator\Http();
		$this->addAuthenticator($authenticator);
		
		//Secondary authentication method if configured: authenticate the user using ActiveDirectory
		$cfg = parse_ini_file('config.ini');
		if($cfg && isset($cfg['host']) && $cfg['host'] != '') {
			require_once dirname(__FILE__) . '/user/authenticator/ldap.php';
			$authenticator = new User\Authenticator\Ldap($cfg['host'],$cfg['username'],$cfg['password'],$cfg['base_dn']);
			if($cfg['realm']) {
				$authenticator->realm = $cfg['realm'];
			}
			$this->addAuthenticator($authenticator);
		}
	}
	
	/**
	 * Add authenticator class that provide the actual authentication mechanisms
	 */
	public function addAuthenticator(User\Authenticator $authenticator) {
		$this->authenticators[] = $authenticator;
	}
	
	/**
	 * Try to identify the user using the available authentication methods
	 * 
	 * @returns User login
	 * @throws UserException User could not be identified using the authenticators available
	 */
	public function identify() {
		//User already identified
		if($this->authenticated) {
			return $this->login;
		}
		else {
			foreach($this->authenticators as $authenticator) {
				try {
					$this->login = $authenticator->identify();
					$this->authenticated = true;
					return $this->login;
				}
				catch(User\AuthenticatorException $e) {
					//Could not identify the user using the authentication method
				}
			}
			throw new UserException("Could not identify the user");
		}
	}
}

class UserException extends \Exception { }

