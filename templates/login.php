<?php
/**
 * Template HTML displayed with http basic (using PHP) authentication
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 * @license http://opensource.org/licenses/LGPL-3.0 LGPL v3
 */
?>
<!DOCTYPE html>
<html>
<head>
<title>Login required</title>
</head>
<body>
<article>
<h1>Login required</h1>
<p>Please enter your ActiveDirectory username &amp; password in order to access this site. <a onclick="location.reload(true); return false;">Try again.</a></p>
<?php
if($_SERVER['SERVER_ADMIN']) {
	$url = 'mailto:' . rawurlencode($_SERVER['SERVER_ADMIN']);
	$url .= '?subject=' . rawurlencode('Login failed');
	$url .= '&amp;body=' . rawurlencode("\n\n-- \nDetails about the incident, please do not edit:\n");
	$url .= rawurlencode('URL: ' . $_SERVER['REQUEST_URI'] . "\n");
	$url .= rawurlencode('Timestamp: ' . date('c') . "\n");
	if($_POST) {
		$url .= rawurlencode('POST data: ' . var_export($_POST, true) . "\n");
	}
	echo 'You can <a href="' . $url . '">contact the administrators</a> for more assistance.' . "\n";
}
?>
</article>
</body>
</html>