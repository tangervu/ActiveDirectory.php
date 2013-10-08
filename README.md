ActiveDirectory.php
===================

User authentication using ActiveDirectory

Example
-------
```php
<?php
require 'activedirectory.php';

$ad = new ActiveDirectory();

//Load AD server settings from ini file
$ad->loadConfig('config.ini');

//Validate user against AD
$login = $_SERVER['PHP_AUTH_USER'];
$password = $_SERVER['PHP_AUTH_PW'];
if($ad->authenticate($login, $password)) {
	echo "User authentication ok\n";
}
else {
	echo "Wrong password!\n";
}

//Get dname for user $login
$dname = $ad->getDname($login);

//List group memberships
print_r($ad->getGroups());

```

License
-------
LGPL v3
