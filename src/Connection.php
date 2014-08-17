<?php
/**
 * ActiveDirectory connection
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 * @license http://opensource.org/licenses/LGPL-3.0 LGPL v3
 */

namespace ActiveDirectory;

class Connection {
	
	protected $conn;
	protected $host;
	protected $user;
	protected $password;
	protected $base_dn;
	
	public $sizelimit = 0;
	public $timelimit = 0;
	
	/**
	 * Define the connection
	 * 
	 * Establishes the connection only when needed or connect() is requested
	 */
	public function __construct($host, $user, $password, $base_dn = null) {
		$this->host = $host;
		$this->user = $user;
		$this->password = $password;
		$this->base_dn = $base_dn;
	}
	
	/**
	 * Establish connection
	 */
	public function connect() {
		if(!$this->conn) {
			$this->conn = ldap_connect($this->host);
			if(!$this->conn) {
				throw new Exception("Could not connect to '{$this->host}'");
			}
			ldap_set_option($this->conn, \LDAP_OPT_PROTOCOL_VERSION, 3);
			ldap_set_option($this->conn, \LDAP_OPT_REFERRALS, 0);
			
			//Login to LDAP server
			if(!ldap_bind($this->conn, $this->user, $this->password)) {
				throw new Exception("Login to '{$this->host}' using '{$this->user}' failed: " . ldap_error($this->conn));
			}
		}
		return $this->conn;
	}
	
	public function getHost() {
		return $this->host;
	}
	
	/**
	 * Execute a ldap query
	 * 
	 * @param $query The query string
	 * @param $attributes Attributes to fetch
	 */
	public function query($query, array $attributes = null, $base_dn = null) {
		$this->connect();
		if(is_null($attributes)) {
			$attributes = array(); // $this->defaultAttributes;
		}
		if(!$base_dn) {
			$base_dn = $this->base_dn;
		}
		$result = ldap_search($this->conn, $base_dn, $query, $attributes, 0, $this->sizelimit, $this->timelimit);
		if($result === false) {
			throw new Exception("Executing query '$query' failed: " . ldap_error($this->conn));
		}
		
		$data = ldap_get_entries($this->conn, $result);
		ldap_free_result($result);
		
		//Clean up the results (TODO find a better way to do this...)
		unset($data['count']);
		foreach($data as $rowNum => $rowValues) { //Result rows
			if(isset($data[$rowNum]['count'])) {
				unset($data[$rowNum]['count']); //Row attribute count
			}
			foreach($rowValues as $attrName => $values) {
				if(is_array($values) && isset($data[$rowNum][$attrName]['count'])) {
					unset($data[$rowNum][$attrName]['count']);
				}
			}
		}
		
		return $data;
	}
}
