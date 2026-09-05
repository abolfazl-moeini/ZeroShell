<?php
class ZS_Engine {
    public static function scanFile($path, $item, $content, $normHash, $rules, $rootDir) {
        if ($content === '' || $content === null) {
            return array('detected' => false, 'reasons' => array());
        }

        $detected = false;
        $reasons  = array();

        // 1. Official WordPress 6.5+ .l10n.php whitelist check
        $isOfficialL10n = (preg_match('/\.l10n\.php$/i', $item) && preg_match('/^<\?php\s+return\s*(\[|array\()/i', ltrim($content)));

        // 2. Normalized Hash rules (run for all files, including l10n)
        if (!empty($rules['hashes']) && is_array($rules['hashes'])) {
            foreach ($rules['hashes'] as $hashRule) {
                if (isset($hashRule['sha256']) && strtolower($normHash) === strtolower($hashRule['sha256'])) {
                    $detected = true;
                    $name = isset($hashRule['name']) ? $hashRule['name'] : 'Known Malicious Hash';
                    $reasons[] = "Normalized Hash Match (" . $name . ")";
                }
            }
        }

        // 3. Double extension check (run for all files)
        if (preg_match('/\.(js|css|png|jpg|jpeg|gif|ico|txt|svg)\.php$/i', $item)) {
            $detected = true;
            $reasons[] = "Dangerous Double Extension (" . $item . ")";
        }

        // If official .l10n.php, skip signatures, structural, and path checks
        if ($isOfficialL10n) {
            return array(
                'detected' => $detected,
                'reasons'  => array_values(array_unique($reasons)),
            );
        }

        // 4. Structural rules
        if (!empty($rules['structural']) && is_array($rules['structural'])) {
            foreach ($rules['structural'] as $structRule) {
                $type = isset($structRule['type']) ? $structRule['type'] : '';
                $name = isset($structRule['name']) ? $structRule['name'] : $type;

                switch ($type) {
                    case 'goto_hex':
                        $minGoto = isset($structRule['min_goto']) ? intval($structRule['min_goto']) : 5;
                        $minHex  = isset($structRule['min_hex_octal']) ? intval($structRule['min_hex_octal']) : 10;
                        $gotoCount = preg_match_all('/\bgoto\s+[a-zA-Z0-9_]+;/i', $content, $mGoto);
                        $hexCount  = preg_match_all('/(\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3})/', $content, $mHex);
                        if ($gotoCount >= $minGoto && $hexCount >= $minHex) {
                            $detected = true;
                            $reasons[] = $name . " ({$gotoCount} gotos, {$hexCount} hex escapes)";
                        }
                        break;

                    case 'goto_eval':
                        $minGoto = isset($structRule['min_goto']) ? intval($structRule['min_goto']) : 3;
                        $gotoCount = preg_match_all('/\bgoto\s+[a-zA-Z0-9_]+;/i', $content, $mGoto);
                        if ($gotoCount >= $minGoto && preg_match('/eval\s*\(/i', $content)) {
                            $detected = true;
                            $reasons[] = $name . " ({$gotoCount} gotos + eval)";
                        }
                        break;

                    case 'ascii_range_decoder':
                        $pattern = isset($structRule['pattern']) ? $structRule['pattern'] : '/(\\\\176|~|\\\\x7e)[\'"]\s*,\s*[\'"](\\\\40|\\\\x20|\s)/';
                        if (preg_match($pattern, $content)) {
                            $detected = true;
                            $reasons[] = $name;
                        }
                        break;

                    case 'goto_math_index':
                        $minGoto = isset($structRule['min_goto']) ? intval($structRule['min_goto']) : 3;
                        $minMath = isset($structRule['min_math']) ? intval($structRule['min_math']) : 5;
                        $gotoCount = preg_match_all('/\bgoto\s+[a-zA-Z0-9_]+;/i', $content, $mGoto);
                        $mathCount = preg_match_all('/\[\s*\d+\s*\+\s*\d+\s*\]/', $content, $mMath);
                        if ($gotoCount >= $minGoto && $mathCount >= $minMath) {
                            $detected = true;
                            $reasons[] = $name . " ({$mathCount} indexed operations)";
                        }
                        break;

                    case 'heavy_hex_octal':
                        $minChunks = isset($structRule['min_chunks']) ? intval($structRule['min_chunks']) : 9;
                        $chunkCount = preg_match_all('/(\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}){4,}/', $content, $mChunks);
                        if ($chunkCount >= $minChunks) {
                            $detected = true;
                            $reasons[] = $name . " ({$chunkCount} encoded chunks)";
                        }
                        break;
                }
            }
        }

        // 5. Signature rules
        if (!empty($rules['signatures']) && is_array($rules['signatures'])) {
            $boundedContent = (strlen($content) > 1048576) ? substr($content, 0, 1048576) : $content;

            foreach ($rules['signatures'] as $sigRule) {
                $type    = isset($sigRule['type']) ? $sigRule['type'] : 'literal_contains';
                $name    = isset($sigRule['name']) ? $sigRule['name'] : 'Signature Match';
                $pattern = isset($sigRule['pattern']) ? $sigRule['pattern'] : '';

                if ($pattern === '') {
                    continue;
                }

                switch ($type) {
                    case 'literal_contains':
                        if (strpos($content, $pattern) !== false) {
                            $detected = true;
                            $reasons[] = $name;
                        }
                        break;

                    case 'regex':
                        // Safe regex execution on bounded window
                        $match = @preg_match($pattern, $boundedContent);
                        if ($match) {
                            $detected = true;
                            $reasons[] = $name;
                        }
                        break;

                    case 'normalized_hash':
                        if (strtolower($normHash) === strtolower($pattern)) {
                            $detected = true;
                            $reasons[] = $name;
                        }
                        break;
                }
            }
        }

        // 6. Path rules
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

                switch ($type) {
                    case 'languages_fake_php':
                        if (strpos($relPath, '/wp-content/languages/') !== false || strpos($relPath, '/classes/wp-content/languages/') !== false) {
                            if (!preg_match('/\.l10n\.php$/i', $item)) {
                                $detected = true;
                                $reasons[] = $name;
                            }
                        }
                        break;

                    case 'uploads_php':
                        if (strpos($relPath, '/wp-content/uploads/') !== false || strpos($relPath, '/classes/wp-content/uploads/') !== false) {
                            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                            if ($ext === 'php' && strtolower($item) !== 'index.php') {
                                $detected = true;
                                $reasons[] = $name;
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
                                $detected = true;
                                $reasons[] = $name;
                                break;
                            }
                        }
                        break;

                    case 'double_extension':
                        $pattern = isset($pathRule['pattern']) ? $pathRule['pattern'] : '/\.(js|css|png|jpg|jpeg|gif|ico|txt|svg)\.php$/i';
                        if (preg_match($pattern, $item)) {
                            $detected = true;
                            $reasons[] = $name . " (" . $item . ")";
                        }
                        break;
                }
            }
        }

        return array(
            'detected' => $detected,
            'reasons'  => array_values(array_unique($reasons)),
        );
    }
}
