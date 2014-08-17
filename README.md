ActiveDirectory.php
===================

User authentication and access control tools for Active Directory

Installation
------------
The recommended way to install Connection.php is through [Composer](http://getcomposer.org).
```json
{
	"require": {
		"tangervu/activedirectory": "dev-master"
	}
}
```

Example
-------
```php
<?php
require('vendor/autoload.php'); //Use composer autoload

$ad = new ActiveDirectory\ActiveDirectory();

//Load AD server settings from ini file
$ad->loadConfig('config.ini');

//Identify user. Uses Apache authentication (mod_auth_kerb) as primary authentication method but has http auth as fallback method.
$login = $ad->identify();

//Get dname for user $login
$dname = $ad->getDname($login);

//Get user information
$userInfo = $ad->getInfo($dname);

//Check if user is member of an AD group (recursive search)
if($ad->isMemberOf($dname, "Test Group", true)) {
	$isMember = true;
}
else {
	$isMember = false;
}
```

License
-------
LGPL v3
