<?php
/**
 * Check if the user is member of group
 * 
 * Authenticates the user (if possible) and displays the username. An exception is thrown if user authentication is not possible.
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 */
?>

<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="get">
Login: <input type="text" name="login" /><br />
Group: <input type="text" name="group" /><br />
Check parent groups: <input type="checkbox" name="recurse" value="1" /><br />
<button type="submit">Check membership</button>
</form>

<?php
if(isset($_GET['group'])) {
	require_once '../vendor/autoload.php';
	$ad = new ActiveDirectory\ActiveDirectory();
	$ad->loadConfig('../config.ini');
	$dname = $ad->getDname($_GET['login']);
	echo "User information for '{$_GET['login']}' (dname: $dname):<br />\n";
	if(isset($_GET['recurse'])) {
		$recurse = true;
	}
	else {
		$recurse = false;
	}
	if($ad->isMemberOf($dname, $_GET['group'], $recurse)) {
		echo "Is member for group '{$_GET['group']}'<br/>\n";
	}
	else {
		echo "Is <strong>not</strong> member for group '{$_GET['group']}'<br/>\n";
	}
}
