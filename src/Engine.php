<?php
class ZS_Engine {
    public static function scanFile($path, $item, $content, $normHash, $rules, $rootDir, $truncated = false) {
        $detected = false;
        $reasons  = array();
        $ruleIds  = array();
        $evidence = array();
        $classes  = array();

        if ($content === '' || $content === null) {
            return array(
                'detected'  => false,
                'reasons'   => array(),
                'rule_ids'  => array(),
                'evidence'  => array(),
                'severity'  => 'none',
                'truncated' => $truncated,
            );
        }

        $looksLikeL10n = (preg_match('/\.l10n\.php$/i', $item) && preg_match('/^<\?php\s+return\s*(\[|array\()/i', ltrim($content)));

        if (!empty($rules['hashes']) && is_array($rules['hashes'])) {
            foreach ($rules['hashes'] as $hashRule) {
                if (isset($hashRule['sha256']) && strtolower($normHash) === strtolower($hashRule['sha256'])) {
                    $detected = true;
                    $name = isset($hashRule['name']) ? $hashRule['name'] : 'Known Malicious Hash';
                    $reasons[] = "Normalized Hash Match (" . $name . ")";
                    if (!empty($hashRule['id'])) {
                        $ruleIds[] = $hashRule['id'];
                    }
                    $classes[] = 'malware';
                }
            }
        }

        if (preg_match('/\.(js|css|png|jpg|jpeg|gif|ico|txt|svg)\.php$/i', $item)) {
            $detected = true;
            $reasons[] = "Dangerous Double Extension (" . $item . ")";
            $ruleIds[] = 'PATH-DOUBLE-EXT';
            $classes[] = 'suspect';
        }

        if (!empty($rules['structural']) && is_array($rules['structural'])) {
            foreach ($rules['structural'] as $structRule) {
                $type = isset($structRule['type']) ? $structRule['type'] : '';
                $name = isset($structRule['name']) ? $structRule['name'] : $type;
                $hit = false;
                $ev = '';

                switch ($type) {
                    case 'goto_hex':
                        $minGoto = isset($structRule['min_goto']) ? intval($structRule['min_goto']) : 5;
                        $minHex  = isset($structRule['min_hex_octal']) ? intval($structRule['min_hex_octal']) : 10;
                        $gotoCount = preg_match_all('/\bgoto\s+[a-zA-Z0-9_]+;/i', $content, $mGoto);
                        $hexCount  = preg_match_all('/(\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3})/', $content, $mHex);
                        if ($gotoCount >= $minGoto && $hexCount >= $minHex) {
                            $hit = true;
                            $ev = $gotoCount . ' gotos, ' . $hexCount . ' hex escapes';
                            $reasons[] = $name . " ({$ev})";
                        }
                        break;

                    case 'goto_eval':
                        $minGoto = isset($structRule['min_goto']) ? intval($structRule['min_goto']) : 3;
                        $gotoCount = preg_match_all('/\bgoto\s+[a-zA-Z0-9_]+;/i', $content, $mGoto);
                        if ($gotoCount >= $minGoto && preg_match('/eval\s*\(/i', $content)) {
                            $hit = true;
                            $ev = $gotoCount . ' gotos + eval';
                            $reasons[] = $name . " ({$ev})";
                        }
                        break;

                    case 'ascii_range_decoder':
                        $pattern = isset($structRule['pattern']) ? $structRule['pattern'] : '/(\\\\176|~|\\\\x7e)[\'"]\s*,\s*[\'"](\\\\40|\\\\x20|\s)/';
                        if (@preg_match($pattern, $content)) {
                            $hit = true;
                            $reasons[] = $name;
                        }
                        break;

                    case 'goto_math_index':
                        $minGoto = isset($structRule['min_goto']) ? intval($structRule['min_goto']) : 3;
                        $minMath = isset($structRule['min_math']) ? intval($structRule['min_math']) : 5;
                        $gotoCount = preg_match_all('/\bgoto\s+[a-zA-Z0-9_]+;/i', $content, $mGoto);
                        $mathCount = preg_match_all('/\[\s*\d+\s*\+\s*\d+\s*\]/', $content, $mMath);
                        if ($gotoCount >= $minGoto && $mathCount >= $minMath) {
                            $hit = true;
                            $ev = $mathCount . ' indexed operations';
                            $reasons[] = $name . " ({$ev})";
                        }
                        break;

                    case 'heavy_hex_octal':
                        $minChunks = isset($structRule['min_chunks']) ? intval($structRule['min_chunks']) : 9;
                        $chunkCount = preg_match_all('/(\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}){4,}/', $content, $mChunks);
                        if ($chunkCount >= $minChunks) {
                            $hit = true;
                            $ev = $chunkCount . ' encoded chunks';
                            $reasons[] = $name . " ({$ev})";
                        }
                        break;
                }

                if ($hit) {
                    $detected = true;
                    if (!empty($structRule['id'])) {
                        $ruleIds[] = $structRule['id'];
                    }
                    if ($ev !== '') {
                        $evidence[] = $ev;
                    }
                    $classes[] = 'malware';
                }
            }
        }

        $boundedContent = (strlen($content) > 1048576) ? substr($content, 0, 1048576) : $content;

        if (!empty($rules['signatures']) && is_array($rules['signatures'])) {
            foreach ($rules['signatures'] as $sigRule) {
                $type    = isset($sigRule['type']) ? $sigRule['type'] : 'literal_contains';
                $name    = isset($sigRule['name']) ? $sigRule['name'] : 'Signature Match';
                $pattern = isset($sigRule['pattern']) ? $sigRule['pattern'] : '';
                $noise   = !empty($sigRule['noise']);
                if ($pattern === '') {
                    continue;
                }
                $hit = false;
                switch ($type) {
                    case 'literal_contains':
                        $hit = (strpos($content, $pattern) !== false);
                        break;
                    case 'regex':
                        $hit = (bool)@preg_match($pattern, $boundedContent);
                        break;
                    case 'normalized_hash':
                        $hit = (strtolower($normHash) === strtolower($pattern));
                        break;
                }
                if ($hit) {
                    $detected = true;
                    $prefix = $noise ? 'Suspicious: ' : '';
                    $reasons[] = $prefix . $name;
                    if (!empty($sigRule['id'])) {
                        $ruleIds[] = $sigRule['id'];
                    }
                    $snippet = self::snippetAround($content, $pattern, 80);
                    if ($snippet !== '') {
                        $evidence[] = $snippet;
                    }
                    $classes[] = $noise ? 'suspect' : 'malware';
                }
            }
        }

        $normRoot = str_replace('\\', '/', rtrim($rootDir, '/\\'));
        $normPath = str_replace('\\', '/', $path);
        if ($normRoot !== '' && strpos($normPath, $normRoot) === 0) {
            $relPath = substr($normPath, strlen($normRoot));
        } else {
            $relPath = $normPath;
        }
        if (substr($relPath, 0, 1) !== '/') {
            $relPath = '/' . $relPath;
        }

        if (!empty($rules['paths']) && is_array($rules['paths'])) {
            foreach ($rules['paths'] as $pathRule) {
                $type = isset($pathRule['type']) ? $pathRule['type'] : '';
                $name = isset($pathRule['name']) ? $pathRule['name'] : 'Path Rule';
                $hit = false;

                switch ($type) {
                    case 'languages_fake_php':
                        if ($looksLikeL10n) {
                            break;
                        }
                        if (strpos($relPath, '/wp-content/languages/') !== false || strpos($relPath, '/classes/wp-content/languages/') !== false) {
                            $hit = true;
                        }
                        break;

                    case 'uploads_php':
                        if (strpos($relPath, '/wp-content/uploads/') !== false || strpos($relPath, '/classes/wp-content/uploads/') !== false) {
                            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                            if ($ext === 'php' || $ext === 'phtml' || $ext === 'php5' || $ext === 'php7') {
                                $hit = true;
                            }
                        }
                        break;

                    case 'rogue_core_path':
                        $targetPaths = isset($pathRule['paths']) && is_array($pathRule['paths'])
                            ? $pathRule['paths']
                            : array('wp-includes/SimplePie/src/HTTP/Psr19Client.php', 'wp-includes/pomo/post.php');
                        foreach ($targetPaths as $targetSub) {
                            $normSub = '/' . ltrim(str_replace('\\', '/', $targetSub), '/');
                            if (strpos($relPath, $normSub) !== false) {
                                $hit = true;
                                break;
                            }
                        }
                        break;

                    case 'double_extension':
                        $pattern = isset($pathRule['pattern']) ? $pathRule['pattern'] : '/\.(js|css|png|jpg|jpeg|gif|ico|txt|svg)\.php$/i';
                        if (@preg_match($pattern, $item)) {
                            $hit = true;
                            $name = $name . " (" . $item . ")";
                        }
                        break;
                }

                if ($hit) {
                    $detected = true;
                    $reasons[] = $name;
                    if (!empty($pathRule['id'])) {
                        $ruleIds[] = $pathRule['id'];
                    }
                    $classes[] = ($type === 'uploads_php' && strtolower($item) === 'index.php') ? 'suspect' : 'malware';
                }
            }
        }

        $severity = 'none';
        if (in_array('malware', $classes, true)) {
            $severity = 'malware';
        } elseif (in_array('suspect', $classes, true) || $detected) {
            $severity = 'suspect';
        }

        return array(
            'detected'  => $detected,
            'reasons'   => array_values(array_unique($reasons)),
            'rule_ids'  => array_values(array_unique($ruleIds)),
            'evidence'  => array_slice(array_values(array_unique($evidence)), 0, 5),
            'severity'  => $severity,
            'truncated' => $truncated,
        );
    }

    private static function snippetAround($content, $needle, $radius) {
        if (!is_string($needle) || $needle === '') {
            return '';
        }
        $pos = strpos($content, $needle);
        if ($pos === false) {
            return '';
        }
        $start = max(0, $pos - $radius);
        $len = strlen($needle) + (2 * $radius);
        $snip = substr($content, $start, $len);
        return str_replace(array("\r", "\n"), ' ', $snip);
    }
}
