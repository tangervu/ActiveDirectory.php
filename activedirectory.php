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
		return $this->conn->query($query, $attributes);
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
		$data = $this->query($query, array('dn'));
		if(count($data) == 0) {
			throw new ActiveDirectoryException("User '$login' not found!");
		}
		else if(count($data) > 1) {
			throw new ActiveDirectoryException("Multiple users with login '$login'");
		}
		return $data[0]['dn'];
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
	 * Search users and groups using common names
	 * 
	 * Tries to sort best answers on top
	 * 
	 * @param $name search string
	 * @returns array(dname => cname)
	 */
	public function search($name) {
		$name = self::quote($name);
		$results = array();
		
		//Exact match
		$query = '(cn=' . $name . ')';
		$result = $this->query($query, array('cn','distinguishedname'));
		foreach($result as $row) {
			$results[$row['distinguishedname'][0]] = $row['cn'][0];
		}
		
		//Beginning of the name has a match
		$query = '(&(cn=' . $name . '*) (!(cn=' . $name . ')))';
		$result = $this->query($query, array('cn','distinguishedname'));
		foreach($result as $row) {
			$results[$row['distinguishedname'][0]] = $row['cn'][0];
		}
		
		//Search term somewhere in the middle of the name
		$query = '(&(cn=*' . $name . '*) (!(cn=' . $name . '*)) (!(cn=' . $name . ')))';
		$result = $this->query($query, array('cn','distinguishedname'));
		foreach($result as $row) {
			$results[$row['distinguishedname'][0]] = $row['cn'][0];
		}
		
		return $results;
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
	 * @param $recurse if true, returns also members from subgroups
	 * @returns array
	 * @throws ActiveDirectoryException
	 */
	public function getMembers($dname, $recurse = false) {
		$data = $this->getInfo($dname, array('member'));
		$members = null;
		if(isset($data['member'])) {
			$members = $data['member'];
		}
		
		if($recurse && $members) {
			//TODO
		}
		
		return $members;
	}
	
	
	/**
	 * Check if user or group is member of a group
	 * 
	 * @param $dname Distinguished name for the user or group
	 * @param $groupDNames Group name (CN), string or array
	 * @param $recurse Check group membership also from parent groups
	 * @returns bool
	 */
	public function isMemberOf($dname, $groupDNames, $recurse = true) {
		
		if(!is_array($groupDNames)) {
			$groupDNames = array($groupDNames);
		}
		
		$parentGroups = array();
		
		//Scan through dname memberships
		$groups = $this->getGroups($dname);
		if($groups) {
			foreach($this->getGroups($dname) as $group) {
				foreach($groupDNames as $groupDName) {
					if($group == $groupDName) {
						return true;
					}
				}
				$parentGroups[] = $group;
			}
		}
		
		//Check if membership can be found from parent group
		if($recurse) {
			foreach($parentGroups as $group) {
				
				//Set AD host for the one that contains the group info
				$parts = self::getDnameComponents($group);
				if(isset($parts['DC'])) {
					$host = implode('.',$parts['DC']);
					$oldHost = $this->getConnectionName();
					$this->useConnection($host);
				}
				
				if($this->isMemberOf($group, $groupDNames)) {
					return true;
				}
				
				//Switch back to previous connection
				if(isset($oldHost)) {
					$this->useConnection($oldHost);
				}
			}
		}
		
		//Didn't find match
		return false;
	}
	
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
	
	/**
	 * Convert ActiveDirectory timestamp into ISO 8601 formatted datetime string
	 */
	public static function getTimestamp($ldapTimeString) {
		$str = $ldapTimeString;
		if($str) {
			//Numeric string, hundreds of nanoseconds starting from 1601-010 00:00 (eg. lastlogon, pwdlastset)
			if(is_numeric($str)) {
				$epoch = ($str / 10000000) - 11644473600;
				return date('Y-m-d',$epoch) . 'T' . date('H:i:s',$epoch) . '+00:00';
			}
			//Textual representation of date & time (eg. mstsexpiredate)
			else {
				$time = substr($str,0,4) . '-' . substr($str,4,2) . '-' . substr($str,6,2) . 'T' . substr($str,8,2) . ':' . substr($str,10,2) . ':' . substr($str,12,2);
				//Timezone info in string
				if(strlen($str) > 14) {
					$timezone = strtoupper(substr($str,-1,1));
					if($timezone == 'Z') {
						$time .= '+00:00';
					}
					else {
						trigger_error("Unknown ActiveDirectory timezone '$timezone'",E_USER_WARNING);
					}
				}
				return $time;
			}
		}
		else {
			return null;
		}
	}
	
	/**
	 * Returns ActiveDirectory datetime in YMD format
	 */
	public static function getADTimestampString($phpTimeString) {
		if($phpTimeString) {
			$date = new DateTime($phpTimeString);
			$utcOffset = $date->getOffset();
			if($utcOffset != 0) {
				$removeSeconds = $utcOffset * -1;
				$date->modify($removeSeconds . ' seconds');
			}
			return $date->format('YmdHis') . '.0Z';
		}
		else {
			return null;
		}
	}
	
	/**
	 * Return DName components
	 *
	 * @param $dnameString DName string
	 * @returns array array(OU => array(...), DC => array())
	 */
	public static function getDnameComponents($dnameString) {
		$results = array();
		$items = preg_split('#(?<!\\\)\,#',trim($dnameString)); //explode(',',trim($dnameString));
		foreach($items as $item) {
			list($key, $data) = preg_split('#(?<!\\\)\=#',$item,2);//explode('=',$item,2);
			if(!isset($results[$key])) {
				$results[$key] = array();
			}
			$results[$key][] = $data;
		}
		return $results;
	}
}

class ActiveDirectoryException extends \Exception {}

