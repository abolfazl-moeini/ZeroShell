<?php
class ZS_Gemini {
    public static $http = null; // Test hook callable

    public static function buildSnippet($content, $matchPattern = '') {
        $totalLen = strlen($content);
        if ($totalLen <= 32768) {
            return $content;
        }

        $headLen = 4096;
        $tailLen = 4096;
        $midWindow = 24576;

        $head = substr($content, 0, $headLen);
        $tail = substr($content, -$tailLen);

        $midPos = (int)($totalLen / 2);
        if ($matchPattern !== '') {
            $found = strpos($content, $matchPattern);
            if ($found !== false) {
                $midPos = $found;
            }
        }

        $startMid = max(0, $midPos - (int)($midWindow / 2));
        if ($startMid + $midWindow > $totalLen) {
            $startMid = max(0, $totalLen - $midWindow);
        }

        $mid = substr($content, $startMid, $midWindow);

        return $head . "\n\n/* ... [ZeroShell: Truncated content window] ... */\n\n" . $mid . "\n\n/* ... [ZeroShell: Truncated content window] ... */\n\n" . $tail;
    }

    public static function redact($text, $rootDir = '') {
        if (!empty($rootDir)) {
            $normRoot = str_replace('\\', '/', $rootDir);
            $text = str_replace(array($rootDir, $normRoot), '', $text);
        }

        // Redact WP config define credentials
        $pattern = "/(define\s*\(\s*['\"](?:DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|DB_USER|DB_NAME|DB_HOST)['\"]\s*,\s*['\"])([^'\"]*)(['\"]\s*\))/i";
        $text = preg_replace($pattern, '$1[REDACTED]$3', $text);

        // Redact direct credential assignments
        $varPattern = "/(\\\$(?:db_password|password|db_user|db_host)\s*=\s*['\"])([^'\"]*)(['\"])/i";
        $text = preg_replace($varPattern, '$1[REDACTED]$3', $text);

        return $text;
    }

    public static function getCacheKey($normHash, $model, $promptVersion, $rulesVersion = 'rules_v1') {
        return $normHash . ':' . $model . ':' . $promptVersion . ':' . $rulesVersion;
    }

    public static function ask($normHash, $filePath, $content, $reasons, $config, $store, $rulesVersion = 'rules_v1') {
        $model = !empty($config['gemini_model']) ? $config['gemini_model'] : 'gemini-2.0-flash';
        $promptVersion = !empty($config['ai_prompt_version']) ? $config['ai_prompt_version'] : 'prompt_v1';
        $cacheKey = self::getCacheKey($normHash, $model, $promptVersion, $rulesVersion);

        // 1. Check AI Cache
        $cached = $store->getAiCache($cacheKey);
        if ($cached !== null && is_array($cached)) {
            $cached['cache_hit'] = true;
            return $cached;
        }

        // 2. Prepare snippet and redactions
        $rootDir = isset($config['root_dir']) ? $config['root_dir'] : ZS_Config::getRoot();
        $snippet = self::buildSnippet($content);
        $redactedSnippet = self::redact($snippet, $rootDir);
        $relPath = self::redact($filePath, $rootDir);
        $flags = is_array($reasons) ? implode('; ', $reasons) : (string)$reasons;

        // 3. Build request payload
        $payload = array(
            'system_instruction' => array(
                'parts' => array(
                    array('text' => 'You are a PHP malware analyst. Classify the snippet as malicious, benign, or uncertain. JSON only.')
                )
            ),
            'contents' => array(
                array(
                    'role'  => 'user',
                    'parts' => array(
                        array('text' => "Path: {$relPath}\nHash: {$normHash}\nLocal flags: {$flags}\n---\n{$redactedSnippet}")
                    )
                )
            ),
            'generationConfig' => array(
                'temperature'      => 0.1,
                'responseMimeType' => 'application/json',
                'responseSchema'   => array(
                    'type'       => 'OBJECT',
                    'properties' => array(
                        'verdict'            => array('type' => 'STRING', 'enum' => array('malicious', 'benign', 'uncertain')),
                        'confidence'         => array('type' => 'NUMBER'),
                        'malware_family'     => array('type' => 'STRING'),
                        'summary'            => array('type' => 'STRING'),
                        'recommended_action' => array('type' => 'STRING', 'enum' => array('quarantine', 'keep', 'manual_review')),
                    ),
                    'required'   => array('verdict', 'confidence', 'summary', 'recommended_action'),
                )
            )
        );
        $payloadJson = json_encode($payload);

        $keys = ZS_Config::getGeminiKeys($config);
        if (empty($keys)) {
            return array(
                'verdict'            => 'uncertain',
                'confidence'         => 0.0,
                'malware_family'     => '',
                'summary'            => 'No Gemini API key configured.',
                'recommended_action' => 'manual_review',
                'error'              => 'no_api_key',
            );
        }

        $url = "https://generativelanguage.googleapis.com/v1beta/models/{$model}:generateContent";
        $attempts = 0;
        $maxAttempts = count($keys);

        while ($attempts < $maxAttempts) {
            $apiKey = ZS_Config::getActiveGeminiKey($config);
            if ($apiKey === null) {
                // All keys are currently cooling down
                return array(
                    'verdict'            => 'uncertain',
                    'confidence'         => 0.0,
                    'malware_family'     => '',
                    'summary'            => 'All Gemini API keys are temporarily rate-limited (cooling down).',
                    'recommended_action' => 'manual_review',
                    'error'              => 'all_cooling',
                    'retry_after'        => 20,
                );
            }

            $headers = array(
                'x-goog-api-key: ' . $apiKey,
                'Content-Type: application/json',
            );

            $response = self::executeHttpRequest($url, $headers, $payloadJson);
            $statusCode = isset($response['status']) ? intval($response['status']) : 0;
            $body = isset($response['body']) ? $response['body'] : '';

            // Check rate limiting or quota error (429 or 403 quota)
            if ($statusCode === 429 || ($statusCode === 403 && (stripos($body, 'quota') !== false || stripos($body, 'RESOURCE_EXHAUSTED') !== false))) {
                ZS_Config::markKeyCooldown($apiKey, 60);
                ZS_Config::rotateGeminiKey($config);
                $attempts++;
                continue;
            }

            // Check if Google returned an invalid-argument error specifically for schema field names, retry once with snake_case
            if ($statusCode === 400 && (
                stripos($body, 'responseMimeType') !== false ||
                stripos($body, 'responseSchema') !== false ||
                stripos($body, 'generationConfig') !== false ||
                (stripos($body, 'invalid') !== false && stripos($body, 'schema') !== false) ||
                stripos($body, 'unknown field') !== false
            )) {
                $snakePayload = $payload;
                unset($snakePayload['generationConfig']);
                $snakePayload['generation_config'] = array(
                    'temperature'        => 0.1,
                    'response_mime_type' => 'application/json',
                    'response_schema'    => array(
                        'type'       => 'OBJECT',
                        'properties' => array(
                            'verdict'            => array('type' => 'STRING', 'enum' => array('malicious', 'benign', 'uncertain')),
                            'confidence'         => array('type' => 'NUMBER'),
                            'malware_family'     => array('type' => 'STRING'),
                            'summary'            => array('type' => 'STRING'),
                            'recommended_action' => array('type' => 'STRING', 'enum' => array('quarantine', 'keep', 'manual_review')),
                        ),
                        'required'   => array('verdict', 'confidence', 'summary', 'recommended_action'),
                    ),
                );
                $retryResp = self::executeHttpRequest($url, $headers, json_encode($snakePayload));
                $retryStatus = isset($retryResp['status']) ? intval($retryResp['status']) : 0;
                $retryBody   = isset($retryResp['body']) ? $retryResp['body'] : '';
                if ($retryStatus >= 200 && $retryStatus < 300) {
                    $statusCode = $retryStatus;
                    $body = $retryBody;
                }
            }

            // Success or other non-retryable response
            if ($statusCode >= 200 && $statusCode < 300) {
                $parsedVerdict = self::parseResponseText($body);
                if ($parsedVerdict !== null) {
                    $verdictRecord = array(
                        'verdict'            => $parsedVerdict['verdict'],
                        'confidence'         => $parsedVerdict['confidence'],
                        'malware_family'     => isset($parsedVerdict['malware_family']) ? $parsedVerdict['malware_family'] : '',
                        'summary'            => isset($parsedVerdict['summary']) ? $parsedVerdict['summary'] : '',
                        'recommended_action' => $parsedVerdict['recommended_action'],
                        'cached_at'          => time(),
                        'model'              => $model,
                        'prompt_version'     => $promptVersion,
                        'rules_version'      => $rulesVersion,
                    );
                    $store->setAiCache($cacheKey, $verdictRecord);
                    $verdictRecord['cache_hit'] = false;
                    return $verdictRecord;
                }
            }

            // If we received an error status
            return array(
                'verdict'            => 'uncertain',
                'confidence'         => 0.0,
                'malware_family'     => '',
                'summary'            => 'Gemini API call failed with status ' . $statusCode . ': ' . substr($body, 0, 200),
                'recommended_action' => 'manual_review',
                'error'              => 'http_error_' . $statusCode,
            );
        }

        return array(
            'verdict'            => 'uncertain',
            'confidence'         => 0.0,
            'malware_family'     => '',
            'summary'            => 'All Gemini API keys failed or are exhausted.',
            'recommended_action' => 'manual_review',
            'error'              => 'all_cooling',
            'retry_after'        => 20,
        );
    }

    public static function parseResponseText($rawBody) {
        $data = @json_decode($rawBody, true);
        if (!is_array($data) || empty($data['candidates'][0]['content']['parts'][0]['text'])) {
            return null;
        }

        $text = trim($data['candidates'][0]['content']['parts'][0]['text']);
        $decoded = @json_decode($text, true);
        if (!is_array($decoded)) {
            // Strip ```json ... ``` markdown block
            $cleaned = preg_replace('/^```(?:json)?\s*/i', '', $text);
            $cleaned = preg_replace('/\s*```$/', '', $cleaned);
            $decoded = @json_decode(trim($cleaned), true);
        }

        if (!is_array($decoded) || !isset($decoded['verdict'])) {
            return null;
        }

        $verdict = strtolower((string)$decoded['verdict']);
        if (!in_array($verdict, array('malicious', 'benign', 'uncertain'), true)) {
            $verdict = 'uncertain';
        }

        $confidence = isset($decoded['confidence']) ? floatval($decoded['confidence']) : 0.0;
        $recAction = isset($decoded['recommended_action']) ? strtolower((string)$decoded['recommended_action']) : 'manual_review';
        if (!in_array($recAction, array('quarantine', 'keep', 'manual_review'), true)) {
            $recAction = 'manual_review';
        }

        return array(
            'verdict'            => $verdict,
            'confidence'         => $confidence,
            'malware_family'     => isset($decoded['malware_family']) ? (string)$decoded['malware_family'] : '',
            'summary'            => isset($decoded['summary']) ? (string)$decoded['summary'] : '',
            'recommended_action' => $recAction,
        );
    }

    public static function executeHttpRequest($url, $headers, $payloadJson) {
        if (is_callable(self::$http)) {
            return call_user_func(self::$http, $url, $headers, $payloadJson);
        }

        $disableFns = explode(',', (string)ini_get('disable_functions'));
        $disableFns = array_map('trim', $disableFns);

        // 1. Try cURL
        if (function_exists('curl_init') && !in_array('curl_exec', $disableFns, true)) {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payloadJson);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

            $body = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = curl_error($ch);
            curl_close($ch);

            if ($body === false) {
                return array('status' => 0, 'body' => 'cURL error: ' . $err);
            }
            return array('status' => $status, 'body' => $body);
        }

        // 2. Fallback to file_get_contents with stream context
        $opts = array(
            'http' => array(
                'method'        => 'POST',
                'header'        => implode("\r\n", $headers) . "\r\n",
                'content'       => $payloadJson,
                'timeout'       => 15,
                'ignore_errors' => true,
            ),
            'ssl' => array(
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ),
        );

        $context = stream_context_create($opts);
        $body = @file_get_contents($url, false, $context);

        $status = 0;
        $hdrVar = 'http_response_header';
        $responseHeaders = function_exists('http_get_last_response_headers')
            ? http_get_last_response_headers()
            : (isset($$hdrVar) ? $$hdrVar : null);
        if (is_array($responseHeaders)) {
            foreach ($responseHeaders as $line) {
                if (preg_match('#HTTP/\S+\s+(\d+)#', $line, $m)) {
                    $status = intval($m[1]);
                    break;
                }
            }
        }

        if ($body === false) {
            return array('status' => 0, 'body' => 'Outbound HTTPS request failed.');
        }

        return array('status' => $status, 'body' => $body);
    }
}
