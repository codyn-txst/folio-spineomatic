<?php

require_once 'config.php';

### Functions ###
function parse_http_response($response, $curl_info, $lc_header_names = true) {
  $parsed_response = array();
  $parsed_response['headers'] = array();
  
  // Set status code in parsed response.
  $parsed_response['status_code'] = $curl_info['http_code'];
  $header = substr($response, 0, $curl_info['header_size']);
  $header_arr = explode("\r\n", $header);

  for ($i = 1; $i < count($header_arr); $i++) {
    $colon_pos = strpos($header_arr[$i], ':');
    if ($colon_pos === false) continue;

    $name_substr = substr($header_arr[$i], 0, $colon_pos);
    $name = $lc_header_names ? strtolower($name_substr) : $name_substr;
    $value = trim(substr($header_arr[$i], $colon_pos + 1));

    // Support multiple Set-Cookie headers
    if (strtolower($name_substr) === 'set-cookie') {
      if (!isset($parsed_response['headers']['set-cookie'])) {
        $parsed_response['headers']['set-cookie'] = [];
      }
      $parsed_response['headers']['set-cookie'][] = $value;
    } else {
      $parsed_response['headers'][$name] = $value;
    }
  }
  // Parse body (remaining) portion.
  $parsed_response['body'] = substr($response, $curl_info['header_size']);

  return $parsed_response;
}

function call_folio_api($api, $curl_options, $lc_header_names = true, $renewal_attempted = false) {
  global $folio_okapi_domain;
  global $folio_okapi_token;

  $all_options = $curl_options + array(
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_HEADER => true,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
  );
  // Set up and send FOLIO API request using PHP cURL extension.
  $request_url = "https://" . $folio_okapi_domain . $api;
  $ch = curl_init($request_url);

  if ($ch === false) {
    return array('error' => 'PHP ERROR: curl_init() failure');
  }

  if (!curl_setopt_array($ch, $all_options)) {
    $curl_error = curl_error($ch);
    curl_close($ch);
    return array('error' => 'PHP ERROR: curl_setopt_array() failure - ' . $curl_error);
  }

  $response = curl_exec($ch);
  $curl_info = curl_getinfo($ch);

  if ($curl_info === false) {
    $curl_error = curl_error($ch);
    curl_close($ch);
    return array('error' => 'PHP ERROR: curl_getinfo() failure - ' . $curl_error);
  }

  curl_close($ch);

  $parsed_response = parse_http_response($response, $curl_info, $lc_header_names);

  if (trim(strtolower($parsed_response['body'])) === 'invalid token') {
    if ($renewal_attempted) {
      return array('error' => 'FOLIO ERROR: Invalid token');
    }

    $cacheObj = get_folio_okapi_token(true);

    if ($cacheObj->error) {
      return array('error' => 'FOLIO ERROR: Token renewal failure');
    }

    $folio_okapi_token = $cacheObj->token;
    return call_folio_api($api, $curl_options, $lc_header_names, true);
  }

  return $parsed_response;
}

function login() {
  global $folio_okapi_tenant;
  global $folio_username;
  global $folio_password;

  // Call FOLIO /authn/login API to request new Okapi token.
  $request_headers = array(
    'Content-type: application/json',
    "X-Okapi-Tenant: {$folio_okapi_tenant}",
  );

  $jsonObj = new stdClass();
  $jsonObj->username = $folio_username;
  $jsonObj->password = $folio_password;
  $json = json_encode($jsonObj);

  $curl_options = array(
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => $request_headers,
    CURLOPT_FRESH_CONNECT => true,
    CURLOPT_FORBID_REUSE => true,
    CURLOPT_POSTFIELDS => $json,
    CURLOPT_RETURNTRANSFER => true
  );

  return call_folio_api('/authn/login-with-expiry', $curl_options);
}

function get_folio_okapi_token($force_new = false) {
  global $token_expiration_days;

  $cache_file = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'cache.json';
  $cacheObj = null;
  $cache_json = file_get_contents($cache_file);

  // Set token object to cache file contents or new object if unable.
  if ($force_new || $cache_json === false || empty($cache_json)) {
    $cacheObj = new stdClass();
  } else {
    $cacheObj = json_decode($cache_json);
  }

  // Create/overwrite cache file if forced, json_decode() failed, the token has
  // no assigned expiration time, the token has expired, or the cached token is
  // empty.
  if (is_null($cacheObj) || empty($cacheObj->tokenExpires) || time() > $cacheObj->tokenExpires || empty($cacheObj->token)) {
    $login_response = login();

    if (!empty($login_response['headers']['set-cookie'])) {
      foreach ($login_response['headers']['set-cookie'] as $cookieHeader) {
        if (stripos($cookieHeader, 'folioAccessToken=') !== false) {
          parse_str(str_replace(';', '&', $cookieHeader), $parsedCookie);
          if (isset($parsedCookie['folioAccessToken'])) {
            $cacheObj->token = $parsedCookie['folioAccessToken'];
          }
        }
      }
    }


    // Fallback to X-Okapi-Token if folioAccessToken not found
    if (empty($cacheObj->token) && isset($login_response['headers']['x-okapi-token'])) {
      $cacheObj->token = $login_response['headers']['x-okapi-token'];
    }

    if (!empty($cacheObj->token)) {
      $cacheObj->tokenExpires = time() + (86400 * $token_expiration_days);
      $cache_json = json_encode($cacheObj);
      if (is_writable($cache_file)) {
        file_put_contents($cache_file, $cache_json);
      }
    } else {
      $cacheObj->error = $login_response['error'] ?? 'Token not found';
    }

  }

  return $cacheObj;
}