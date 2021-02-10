<?php

/*
  PHP script to handle file uploads and downloads for mod_http_upload_external imported from Prosody Modules

  ** How to use?

  Drop this file somewhere it will be served by your web server. Edit the config options below.

  In Metronome set:

	http_file_external_url = "https://your.example.com/path/to/share.php/"
	http_file_secret = "this is your secret string"
	http_file_delete_secret = "this is your secret string"

  ** Metronome's License

  Copyright (c) 2018, Marco Cirillo (LW.Org) <maranda@lightwitch.org>

  Permission to use, copy, modify, and/or distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  
  ** Original License

  (C) 2016 Matthew Wild <mwild1@gmail.com>

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software
  and associated documentation files (the "Software"), to deal in the Software without restriction,
  including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial
  portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
  BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
/*         CONFIGURATION OPTIONS                   */
/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

/* Change this to a directory that is writable by your web server, but is outside your web root */
$CONFIG_STORE_DIR = '/var/xmpp-upload/';

/* This must be the same as 'http_file_secret' that you set in Metronome's config file */
$CONFIG_SECRET = '{{ HTTP_FILE_SECRET }}';

/* This must be the same as 'http_file_delete_secret' that you set in Metronome's config file */
$DELETE_SECRET = '{{ HTTP_FILE_DELETE_SECRET }}';

/* For people who need options to tweak that they don't understand... here you are */
$CONFIG_CHUNK_SIZE = 4096;

/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
/*         END OF CONFIGURATION                    */
/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

/* Do not edit below this line unless you know what you are doing (spoiler: nobody does) */

$upload_file_name = substr($_SERVER['PHP_SELF'], strlen($_SERVER['SCRIPT_NAME'])+1);
$store_file_name = $CONFIG_STORE_DIR . '/store-' . hash('sha256', $upload_file_name);

$request_method = $_SERVER['REQUEST_METHOD'];

/* Set CORS headers */
header('Access-Control-Allow-Methods: DELETE, GET, HEAD, OPTIONS, PUT');
header('Access-Control-Allow-Headers: Content-Type, Origin, X-Requested-With');
header('Access-Control-Allow-Origin: *');

if(array_key_exists('token', $_GET) === TRUE && ($request_method === 'PUT' || $request_method === 'DELETE')) {
//	error_log(var_export($_SERVER, TRUE));
	$upload_file_size = $_SERVER['CONTENT_LENGTH'];
	$upload_token = $_GET['token'];

	if(array_key_exists('CONTENT_TYPE', $_SERVER) === TRUE) {
		$upload_file_type = $_SERVER['CONTENT_TYPE'];
	} else {
		$upload_file_type = 'application/octet-stream';
	}

	// Imagine being able to store the file data in the content-type!
	if(strlen($upload_file_type) > 255) {
		header('HTTP/1.0 400 Bad Request');
		exit;
	}

	if($request_method === 'PUT') {
		$calculated_token = hash_hmac('sha256', "$upload_file_name\0$upload_file_size\0$upload_file_type", $CONFIG_SECRET);
		if(function_exists('hash_equals')) {
			if(hash_equals($calculated_token, $upload_token) !== TRUE) {
				error_log("Token mismatch: calculated $calculated_token got $upload_token");
				header('HTTP/1.0 403 Forbidden');
				exit;
			}
		}
		else {
			if($upload_token !== $calculated_token) {
				error_log("Token mismatch: calculated $calculated_token got $upload_token");
				header('HTTP/1.0 403 Forbidden');
				exit;
			}
		}
	
		/* Open a file for writing */
		$store_file = fopen($store_file_name, 'x');

		if($store_file === FALSE) {
			header('HTTP/1.0 409 Conflict');
			exit;
		}

		/* PUT data comes in on the stdin stream */
		$incoming_data = fopen('php://input', 'r');

		/* Read the data a chunk at a time and write to the file */
		while ($data = fread($incoming_data, $CONFIG_CHUNK_SIZE)) {
  			fwrite($store_file, $data);
		}

		/* Close the streams */
		fclose($incoming_data);
		fclose($store_file);
		file_put_contents($store_file_name.'-type', $upload_file_type);
		header('HTTP/1.0 201 Created');
	} else {
		$calculated_token = hash_hmac('sha256', "$upload_file_name\0$DELETE_SECRET", $CONFIG_SECRET);
		if(function_exists('hash_equals')) {
			if(hash_equals($calculated_token, $upload_token) !== TRUE) {
				error_log("Token mismatch: calculated $calculated_token got $upload_token");
				header('HTTP/1.0 403 Forbidden');
				exit;
			}
		}
		else {
			if($upload_token !== $calculated_token) {
				error_log("Token mismatch: calculated $calculated_token got $upload_token");
				header('HTTP/1.0 403 Forbidden');
				exit;
			}
		}

		$deleted_file = unlink($store_file_name);
		$deleted_data = unlink($store_file_name.'-type');

		if($deleted_file === TRUE and $deleted_data === TRUE) {
			header('HTTP/1.0 204 No Content');
		} else {
			header('HTTP/1.0 202 Accepted');
		}
	}
} else if($request_method === 'GET' || $request_method === 'HEAD') {
	// Send file (using X-Sendfile would be nice here...)
	if(file_exists($store_file_name)) {
		$mime_type = file_get_contents($store_file_name.'-type');
		if($mime_type === FALSE) {
			$mime_type = 'application/octet-stream';
			header('Content-Disposition: attachment');
		}
		header('Content-Type: '.$mime_type);
		header('Content-Length: '.filesize($store_file_name));
		header("Content-Security-Policy: \"default-src 'none'\"");
		header("X-Content-Security-Policy: \"default-src 'none'\"");
		header("X-WebKit-CSP: \"default-src 'none'\"");
		if($request_method !== 'HEAD') {
			readfile($store_file_name);
		}
	} else {
		header('HTTP/1.0 404 Not Found');
	}
} else if($request_method === 'OPTIONS') {
} else {
	header('HTTP/1.0 400 Bad Request');
}

exit;
