<?php
/**
 * Show user information
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 */
?>

<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="get">
Login: <input type="text" name="login" />
<button type="submit">Show info</button>
</form>

<?php
if(isset($_GET['login'])) {
	require_once '../activedirectory.php';
	$ad = new ActiveDirectory();
	$ad->loadConfig('../config.ini');
	$dname = $ad->getDname($_GET['login']);
	echo "<pre>\n";
	echo "User information for '{$_GET['login']}' (dname: $dname):\n";
	print_r($ad->getInfo($dname));
	echo "</pre>\n";
}
