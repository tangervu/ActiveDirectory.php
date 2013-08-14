<?php
/**
 * Tools for misc ActiveDirectory (LDAP) actions
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 */

require_once dirname(__FILE__) . '/activedirectory/connection.php';


class ActiveDirectory {
	
	protected $conn; //Currently used connection
	protected $connName; //Name for the currently used connection
	protected $connPool = array(); //Connections available
	protected $connAliases = array(); //Alias names for connections
	
	//Default settings for active directory connections
	public $sizelimit = 0;
	public $timelimit = 0;
	
	public function __construct() { }
	
	public function loadConfig($iniFile) {
		$cfg = parse_ini_file($iniFile,true);
		if($cfg === false) {
			throw new ActiveDirectoryException("Could not read config file '$iniFile'");
		}
		
		//General settings
		$defaultHost = null;
		if(isset($cfg['general'])) {
			if(isset($cfg['general']['timelimit'])) {
				$this->timelimit = (int)$cfg['general']['timelimit'];
			}
			if(isset($cfg['general']['sizelimit'])) {
				$this->sizelimit = (int)$cfg['general']['sizelimit'];
			}
			if(isset($cfg['general']['default_host'])) {
				$defaultHost = $cfg['general']['default_host'];
			}
			unset($cfg['general']);
		}
		
		//AD server settings
		foreach($cfg as $name => $vals) {
			$conn = new ActiveDirectory\Connection($vals['host'], $vals['username'], $vals['password'], $vals['base_dn']);
			$this->addConnection($conn, $name);
			if(isset($vals['aliases']) && trim($vals['aliases']) != '') {
				foreach(explode(',',trim($vals['aliases'])) as $alias) {
					$alias = trim($alias);
					if($alias != '') {
						$this->addConnectionAlias($name, $alias);
					}
				}
			}
		}
		if($defaultHost) {
			$this->useConnection($defaultHost);
		}
	}
	
	/**
	 * Add new ActiveDirectory server
	 */
	public function addConnection(ActiveDirectory\Connection $conn, $name = 'default') {
		$name = strtolower($name);
		$conn->timelimit = $this->timelimit;
		$conn->sizelimit = $this->sizelimit;
		if(!$this->conn) { //First connection is also the default connection
			$this->conn = $conn;
			$this->connName = $name;
		}
		$this->connPool[$name] = $conn;
	}
	
	/**
	 * Add alias name for connection
	 */
	public function addConnectionAlias($connectionName, $alias) {
		if(!isset($this->connPool[$connectionName])) {
			throw new ActiveDirectoryException("Connection '$connectionName' is not defined!");
		}
		if(!isset($this->connAliases[$connectionName])) {
			$this->connAliases[$connectionName] = array();
		}
		$this->connAliases[$connectionName][] = strtolower($alias);
	}
	
	/**
	 * Select the connection to use
	 */
	public function useConnection($name) {
		$name = strtolower($name);
		$foundConnection = false;
		if(isset($this->connPool[$name])) {
			$this->conn = $this->connPool[$name];
			$this->connName = $name;
			$foundConnection = true;
		}
		else { //Search connection from aliases
			foreach($this->connAliases as $connName => $aliases) {
				if(in_array($name, $aliases)) {
					$this->conn = $this->connPool[$connName];
					$this->connName = $connName;
					$foundConnection = true;
					break;
				}
			}
		}
		if(!$foundConnection) {
			throw new ActiveDirectoryException("Unknown connection '$name'");
		}
	}
	
	/**
	 * Get the name for current connection in use
	 */
	public function getConnectionName() {
		if($this->conn) {
			return $this->connName;
		}
		else {
			throw new ActiveDirectoryException("No connection in use");
		}
	}
	
	
	/**
	 * Base DN used on LDAP queries
	 */
	public function setBaseDn($dn) {
		$this->conn->base_dn = $dn;
	}
	public function getBaseDn() {
		return $this->conn->base_dn;
	}
	
	
	
	/**
	 * Execute a ldap query
	 * 
	 * @param $query The query string
	 * @param $attributes Attributes to fetch
	 */
	public function query($query, array $attributes = null) {
		if(!$this->conn) {
			throw new ActiveDirectoryException("No connection");
		}
		return $this->conn->query($query, $attributes, $this->base_dn, $this->sizelimit, $this->timelimit);
	}
	
	
	/**
	 * Get information from a user/group
	 * 
	 * @param $dname
	 * @returns array
	 * @throws ActiveDirectoryException
	 */
	public function getInfo($dname, array $attributes = null) {
		$query = '(distinguishedname=' . self::quote($dname) .')';
		
		//Fetch direct user memberships
		$data = $this->query($query, $attributes);
		if(count($data) == 0) {
			throw new ActiveDirectoryException("DName '$dname' not found!");
		}
		else if(count($data) > 1) {
			throw new ActiveDirectoryException("Multiple users with DName '$dname'");
		}
		
		return $data[0];
	}
	
	
	/**
	 * Return DName for login
	 * 
	 * @param $login
	 * @returns Dname
	 * @throws ActiveDirectoryException Not able to return dname
	 */
	public function getDname($login) {
		$query = '(samaccountname=' . self::quote($login) . ')';
		$data = $this->query($query, array('distinguishedname'));
		if(count($data) == 0) {
			throw new ActiveDirectoryException("User '$login' not found!");
		}
		else if(count($data) > 1) {
			throw new ActiveDirectoryException("Multiple users with login '$login'");
		}
		return $data[0]['distinguishedname'][0];
	}
	
	
	/**
	 * Return login for DName
	 * 
	 * @param $dname
	 * @returns Dname
	 * @throws ActiveDirectoryException Not able to return dname
	 */
	public function getLogin($dname) {
		$data = $this->getInfo($dname, array('samaccountname'));
		if(isset($data['samaccountname'])) {
			return $data['samaccountname'][0];
		}
		else {
			return null;
		}
	}
	
	
	
	/**
	 * Return name for DName
	 * 
	 * @param $dname
	 * @returns Dname
	 * @throws ActiveDirectoryException Not able to return dname
	 */
	public function getName($dname) {
		$data = $this->getInfo($dname, array('cn'));
		if(isset($data['cn'])) {
			return $data['cn'][0];
		}
		else {
			return null;
		}
	}
	
	
	
	/**
	 * List direct memberships for user/group
	 * 
	 * @param $dname
	 * @returns array
	 * @throws ActiveDirectoryException
	 */
	public function getGroups($dname) {
		$data = $this->getInfo($dname, array('memberOf'));
		if(isset($data['memberof'])) {
			return $data['memberof'];
		}
		else {
			return null;
		}
	}
	
	
	/**
	 * List direct members for a group
	 * 
	 * @param $dname
	 * @returns array
	 * @throws ActiveDirectoryException
	 */
	public function getMembers($dname) {
		$data = $this->getInfo($dname, array('member'));
		if(isset($data['member'])) {
			return $data['member'];
		}
		else {
			return null;
		}
	}
	
	
	/**
	 * Check if user or group is member of a group
	 * 
	 * @param $dname Distinguished name for the user or group
	 * @param $group Group name (CN), string or array
	 * @param $recurse Check group membership also from parent groups
	 * @returns bool
	 */
	/*
	public function isMemberOf($dname, $group, $recurse = true) {
		$query = '(distinguishedname=' . self::quote($dname) .')';
		
		//Fetch direct user memberships
		$data = $this->query($query, array('memberOf'));
		if(count($data) == 0) {
			throw new ActiveDirectoryException("DName '$dname' not found!");
		}
		else if(count($data) > 1) {
			throw new ActiveDirectoryException("Multiple users with DName '$dname'");
		}
		
		$groups = $data[0]['memberof'];
		foreach($groups as $groupDn) {
			
			
		}
		
		print_r($groups);
		
		
	}
	*/
	
	/**
	 * Authenticate a user
	 * 
	 * @param $login Username. Can be in form of "login", "REALM\login" or "login@REALM"
	 * @param $password 
	 * @returns boolean
	 * @throws ActiveDirectoryException
	 */
	public function authenticate($login, $password) {
		
		if(!$this->conn) {
			throw new ActiveDirectoryException("No connection to ActiveDirectory");
		}
		
		//Try to login to the ldap server using the user login & password
		$host = $this->conn->getHost();
		$conn = ldap_connect($host);
		if(!$conn) {
			throw new ActiveDirectoryException("Unable to connect to '$host'");
		}
		ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
		if(@ldap_bind($conn, $login, $password)) {
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

