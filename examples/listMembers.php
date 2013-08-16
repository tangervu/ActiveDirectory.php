<?php
/**
 * List members belonging to a group
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 */
?>

<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="get">
Group DName: <input type="text" name="group" /><br />
List members also from subgroups: <input type="checkbox" name="recurse" value="1" /><br />
<button type="submit">List members</button>
</form>

<?php
if(isset($_GET['group'])) {
	require_once '../activedirectory.php';
	$ad = new ActiveDirectory();
	$ad->loadConfig('../config.ini');
	
	if(isset($_GET['recurse'])) {
		$recurse = true;
	}
	else {
		$recurse = false;
	}
	
	echo "<pre>\n";
	print_r($ad->getMembers($_GET['group'], $recurse));
	echo "</pre>\n";
	
	/*
	$dname = $ad->getDname($_GET['login']);
	echo "User information for '{$_GET['login']}' (dname: $dname):<br />\n";
	if($ad->isMemberOf($dname, $_GET['group'])) {
		echo "Is member for group '{$_GET['group']}'<br/>\n";
	}
	else {
		echo "Is <strong>not</strong> member for group '{$_GET['group']}'<br/>\n";
	}
	*/
}
