<?php
/**
 * How to identify the current user
 * 
 * Authenticates the user (if possible) and displays the username. An exception is thrown if user authentication is not possible.
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 */

require_once '../user.php';
$user = new User();
$user->loadConfig('../config.ini');
echo $user->identify() . "\n";
