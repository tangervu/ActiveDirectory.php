<?php
/**
 * Tools for misc ActiveDirectory (LDAP) actions
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 */

class ActiveDirectory {
	
	protected $conn;
	protected $host;
	protected $base_dn;
	
	/**
	 * @param $host Hostname for the ActiveDirectory server
	 * @param $user Username
	 * @param $password Password
	 * @param $base_dn Base DN for the queries
	 */
	public function __construct($host, $user, $password, $base_dn = null) {
		
		$this->host = $host;
		$this->conn = ldap_connect($host);
		if(!$this->conn) {
			throw new ActiveDirectoryException("Could not connect to '$host'");
		}
		ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($this->conn, LDAP_OPT_REFERRALS, 0);
		
		//Login to LDAP server
		if(!ldap_bind($this->conn, $user, $password)) {
			throw new ActiveDirectoryException("Login to '$host' using '$user' failed: " . ldap_error($this->conn));
		}
		
		if($base_dn) {
			$this->setBaseDn($base_dn);
		}
	}
	public function __destruct() {
		ldap_unbind($this->conn);
	}
	
	
	
	/**
	 * Base DN used on LDAP queries
	 */
	public function setBaseDn($dn) {
		$this->base_dn = $dn;
	}
	public function getBaseDn() {
		return $this->base_dn;
	}
	
	
	
	/**
	 * Execute a ldap query
	 * 
	 * @param $query The query string
	 * @param $attributes Attributes to fetch
	 */
	public function query($query, array $attributes = null, $sizelimit = 0, $timelimit = 0) {
		$result = ldap_search($this->conn, $this->base_dn, $query, $attributes, 0, $sizelimit, $timelimit);
		if($result === false) {
			throw new ActiveDirectoryException("Executing query '$query' failed: " . ldap_error($this->conn));
		}
		
		$data = ldap_get_entries($this->conn, $result);
		unset($data['count']);
		ldap_free_result($result);
		
		return $data;
	}
	
	/**
	 * Authenticate a user
	 */
	public function authenticate($user, $password) {
		//Fetch user dn
		$query = '(samaccountname=' . self::quote($user) .')';
		$data = $this->query($query,array('dn'));
		if(count($data) == 0) {
			return false;
		}
		else if(count($data) > 1) {
			throw new ActiveDirectoryException("Multiple users with login '$user'");
		}
		$dname = $data[0]['dn'];
		
		//Try to login to the ldap server using the user login & password
		$conn = ldap_connect($this->host);
		if(!$conn) {
			throw new ActiveDirectoryException("Unable to connect to '{$this->host}'");
		}
		ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
		if(@ldap_bind($conn, $dname, $password)) {
			$result = true;
		}
		else {
			$result = false;
		}
		ldap_unbind($conn);
		
		return $result;
	}
	
	/**
	 * Quote illegal char for LDAP query texts
	 */
	public static function quote($string) {
		$metaChars = array('*','(',')','\\',chr(0));
		foreach($metaChars as $key => $value) {
			$quotedMetaChars[$key] = '\\' . str_pad(dechex(ord($value)),2,'0');
		}
		return str_replace($metaChars,$quotedMetaChars,$string);
	}
		
}

class ActiveDirectoryException extends \Exception {}

