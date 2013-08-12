<?php
/**
 * Authenticator using LDAP (ActiceDirectory) server as a backend
 * 
 * @author Tuomas Angervuori <tuomas.angervuori@gmail.com>
 */

namespace User\Authenticator {
	
	require_once dirname(__FILE__) . '/../authenticator.php';
	
	class Ldap implements \User\Authenticator {
		
		protected $host;
		protected $user;
		protected $password;
		protected $base_dn;
		
		public $realm = 'Password protected site';
		
		/**
		 * Define the LDAP server attributes
		 */
		public function __construct($host, $user, $password, $base_dn) {
			$this->host = $host;
			$this->user = $user;
			$this->password = $password;
			$this->base_dn = $base_dn;
		}
		
		public function identify() {
			
			//User has entered username & password
			if(isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
				
				require_once dirname(__FILE__) . '/../../activedirectory.php';
				$ad = new \ActiveDirectory($this->host, $this->user, $this->password, $this->base_dn);
				
				//Verify the username on the AD server
				if($ad->authenticate($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
					return $_SERVER['PHP_AUTH_USER'];
				}
			}
			
			//No login info provided or login failed, asking for username and password
			header('WWW-Authenticate: Basic realm="' . $this->realm . '"',true,401);
			
			//Display authentication information from a template html
			include dirname(__FILE__) . '/../../templates/login.php';
			
			/*
			//
			require_once dirname(__FILE__) . '/../../view/html.php';
			$view = new \View\Html('Log in');
			$view->setHttpHeader('WWW-Authenticate','Basic realm="' . $this->realm . '"',401);
			
			require_once dirname(__FILE__) . '/../../content/article.php';
			$article = new \Content\Article('Käyttäjän tunnistus');
			$article->isHtml(true);
			$url = htmlspecialchars($_SERVER['REQUEST_URI']);
			$article->addBodyPart('Päästäksesi käyttämään sivustoa sinun tulee kirjautua sisään järjestelmään (tunnus ja salasana samat kuin kirjautuessasi sisään tietokoneellesi, esim. <em>fimeikma</em>). <a href="' . $url . '" onclick="location.reload(true); return false;">Yritä uudelleen</a>.');
			if($_SERVER['SERVER_ADMIN']) {
				$mail = htmlspecialchars($_SERVER['SERVER_ADMIN']);
				$mail .= '?subject=' . rawurlencode('Ongelmia sisäänkirjautumisessa');
				$mail .= '&amp;body=' . rawurlencode("\n\n-- \nTarkempia tietoja, älä tee muutoksia:\n");
				$mail .= rawurlencode('Ajankohta: ' . date('d.m.Y H:i:s') . "\n");
				$mail .= rawurlencode('Sijainti: ' . $_SERVER['REQUEST_URI'] . "\n");
				if($_POST) {
					$mail .= rawurlencode('Tiedot: ' . var_export($_POST, true) . "\n");
				}
				$article->addBodyPart('Ongelmatapauksissa ota yhteys <a href="mailto:' . $mail . '">ylläpitoon</a>');
			}
			
			$view->addContent($article);
			$view->send();
			*/
			exit;
			
		}
	}
}
