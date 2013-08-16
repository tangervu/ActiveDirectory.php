<?php
/**
 * Search user or group
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 */
?>

<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="get">
Search: <input type="text" name="search" />
<button type="submit">Search</button>
</form>

<?php
if(isset($_GET['search'])) {
	require_once '../activedirectory.php';
	$ad = new ActiveDirectory();
	$ad->loadConfig('../config.ini');
	$results = $ad->search($_GET['search']);
	echo "<pre>\n";
	echo "Search results for '{$_GET['search']}':\n";
	print_r($results);
	echo "</pre>\n";
}
