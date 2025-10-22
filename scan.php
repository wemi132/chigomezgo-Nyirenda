<?php
'base64_decode' => 'has-base64',
'window.location' => 'redirect-script',
'data:text/html' => 'data-url'
];


foreach($patterns as $pat => $flag){
if(strpos($lower, $pat) !== false){
$suspicious[] = $flag;
}
}


// Heuristic risk scoring
$risk = ['level'=>'low', 'reason'=>'No obvious issues detected'];
$score = 0;
$score += in_array('host-is-ip', $suspicious) ? 3 : 0;
$score += in_array('blacklisted-domain', $suspicious) ? 5 : 0;
$score += in_array('cannot-resolve', $suspicious) ? 2 : 0;
$score += in_array('resolves-to-private-ip', $suspicious) ? 4 : 0;
$score += preg_grep('/^has-/', $suspicious) ? 2 : 0;
$score += preg_grep('/^contains-/', $suspicious) ? 2 : 0;


if($http_code && ($http_code >= 400 || $http_code < 100)) $score += 2;
if($redirect_count > 3) $score += 2;


if($score >= 8) { $risk = ['level'=>'high','reason'=>'Multiple suspicious indicators']; }
elseif($score >= 4) { $risk = ['level'=>'medium','reason'=>'Some suspicious indicators were found']; }


// Prepare sample (trim whitespace and limit length)
$sample = null;
if(!empty($buffer)){
$sample = trim(preg_replace('/\s+/', ' ', substr($buffer, 0, 8000)));
}


$response = [
'input_url' => $url,
'final_url' => $final_url,
'http_code' => $http_code,
'content_type' => $content_type,
'redirect_count' => $redirect_count,
'server' => $info['server'] ?? null,
'resolved_ip' => $resolved ?? null,
'suspicious' => array_values(array_unique($suspicious)),
'risk' => $risk,
'sample' => $sample,
'curl_error' => $curlErr ?: null,
'meta' => $info,
];


echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);