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
	protected $ad;
	
	public function __construct() {
		/*
		//Primary authentication method: rely on web servers user authentication
		require_once dirname(__FILE__) . '/user/authenticator/http.php';
		$authenticator = new User\Authenticator\Http();
		$this->addAuthenticator($authenticator);
		
		//Secondary authentication method if configured: authenticate the user using ActiveDirectory
		$cfg = parse_ini_file('config.ini',true);
		print_r($cfg);
		exit;
		if($cfg) {
			
			//Uncategorized connection
			if(isset($cfg['host'])) {
			
			if(isset($cfg['realm'])) {
			
			
			
			//&& isset($cfg['host']) && $cfg['host'] != '') {
			$ad = $this->connectToAd($cfg['host'],$cfg['username'],$cfg['password'],$cfg['base_dn']);
			
			require_once dirname(__FILE__) . '/user/authenticator/ldap.php';
			$authenticator = new User\Authenticator\Ldap($ad);
			if($cfg['realm']) {
				$authenticator->realm = $cfg['realm'];
			}
			$this->addAuthenticator($authenticator);
		}
		*/
	}
	
	/**
	 * Load settings for user authentication
	 */
	public function loadConfig($iniFile) {
		$cfg = parse_ini_file($iniFile,true);
		if($cfg === false) {
			throw new UserException("Could not read config file '$iniFile'");
		}
		
		//General settings
		$realm = null;
		if(isset($cfg['general'])) {
			
			if(isset($cfg['general']['http_authentication']) && $cfg['general']['http_authentication']) {
				require_once dirname(__FILE__) . '/user/authenticator/http.php';
				$authenticator = new User\Authenticator\Http();
				$this->addAuthenticator($authenticator);
			}
			
			if(isset($cfg['general']['realm'])) {
				$realm = trim($cfg['general']['realm']);
			}
			
			unset($cfg['general']);
		}
		
		//AD server settings for ldap authenticator
		if($cfg) {
			require_once dirname(__FILE__) . '/activedirectory.php';
			$ad = new ActiveDirectory();
			$ad->loadConfig($iniFile);
			require_once dirname(__FILE__) . '/user/authenticator/ldap.php';
			$authenticator = new \User\Authenticator\Ldap($ad);
			if($realm) {
				$authenticator->realm = $realm;
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
	 * Setup ActiveDirectory connection
	 * 
	 */
	public function connectToAd($host, $username, $password, $base_dn = null) {
		require_once dirname(__FILE__) . '/activedirectory.php';
		$this->ad = new ActiveDirectory($host, $username, $password, $base_dn);
		return $this->ad;
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
	
	
	/**
	 * Check if the user is member of group
	 * 
	 * @param $group Name (CN) of the group
	 * @returns bool
	 */
	public function isMemberOf($group) {
		if(!$this->ad) {
			throw new UserException("Connection to ActiveDirectory is not established");
		}
		
		$dname = $this->ad->getDName($this->identify());
		
		return $this->ad->isMemberOf($dname, $group);
	}
}

class UserException extends \Exception { }

