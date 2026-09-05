<?php
/**
 * ZeroShell Malware Cleaner — Test Runner
 * Self-contained CLI test suite (no external dependencies, PHP 7.4+)
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

$repoRoot = dirname(dirname(__FILE__));
require_once $repoRoot . '/src/Hash.php';
require_once $repoRoot . '/src/Config.php';
require_once $repoRoot . '/src/I18n.php';
require_once $repoRoot . '/src/Rules.php';
require_once $repoRoot . '/src/Store.php';
require_once $repoRoot . '/src/Quarantine.php';
require_once $repoRoot . '/src/Engine.php';
require_once $repoRoot . '/src/Gemini.php';
require_once $repoRoot . '/src/Share.php';
require_once $repoRoot . '/src/Http.php';
require_once $repoRoot . '/src/Ui.php';

$testsPassed = 0;
$testsFailed = 0;

function run_test($name, $callable) {
    global $testsPassed, $testsFailed;
    echo "Running: {$name}... ";
    try {
        call_user_func($callable);
        echo "PASS\n";
        $testsPassed++;
    } catch (Exception $e) {
        echo "FAIL\n  Error: " . $e->getMessage() . "\n";
        $testsFailed++;
    }
}

function assert_true($cond, $msg = 'Expected true') {
    if (!$cond) {
        throw new Exception($msg);
    }
}

function assert_false($cond, $msg = 'Expected false') {
    if ($cond) {
        throw new Exception($msg);
    }
}

function assert_equals($expected, $actual, $msg = 'Values not equal') {
    if ($expected !== $actual) {
        throw new Exception("{$msg}: expected " . var_export($expected, true) . ", got " . var_export($actual, true));
    }
}

echo "=== ZeroShell Test Suite ===\n\n";

// -------------------------------------------------------------
// Test 1: JSON rules file parses; every id unique
// -------------------------------------------------------------
run_test('Test 1: JSON rules file parses and has unique IDs', function() use ($repoRoot) {
    $dbFile = $repoRoot . '/rules/database.json';
    assert_true(file_exists($dbFile), 'rules/database.json missing');
    $raw = file_get_contents($dbFile);
    $data = json_decode($raw, true);
    assert_true(is_array($data), 'Invalid JSON in database.json');
    assert_true(isset($data['schema_version']), 'schema_version missing');

    $ids = array();
    $sections = array('hashes', 'signatures', 'structural', 'paths');
    $totalRules = 0;

    foreach ($sections as $sec) {
        if (!empty($data[$sec])) {
            foreach ($data[$sec] as $r) {
                assert_true(!empty($r['id']), "Rule missing ID in section {$sec}");
                assert_false(isset($ids[$r['id']]), "Duplicate rule ID found: {$r['id']}");
                $ids[$r['id']] = true;
                $totalRules++;
            }
        }
    }
    assert_true($totalRules > 20, "Expected > 20 rules, found {$totalRules}");
});

// -------------------------------------------------------------
// Test 2: Two Nirmala-like fixtures produce same normalized hash
// -------------------------------------------------------------
run_test('Test 2: Normalization produces identical hash for Nirmala variants & verifies canonical hash', function() use ($repoRoot) {
    $f1 = file_get_contents($repoRoot . '/tests/fixtures/nirmala_pad_1.php');
    $f2 = file_get_contents($repoRoot . '/tests/fixtures/nirmala_pad_2.php');

    $norm1 = ZS_Hash::normalized($f1);
    $norm2 = ZS_Hash::normalized($f2);

    assert_true($norm1 === $norm2, 'Normalized hashes must match despite different padding and const names');

    // Test the known database hash separately
    $canonicalKnownHash = '6a3eb5b8e3f9a0d81b2456387a2f5f9369f052685168090aeb0415ac42e4a1bd';
    $rules = ZS_Rules::bundled();
    $foundInDb = false;
    foreach ($rules['hashes'] as $hr) {
        if (strtolower($hr['sha256']) === $canonicalKnownHash) {
            $foundInDb = true;
            break;
        }
    }
    assert_true($foundInDb, 'Known hash must exist in rules database');

    $dummyContent = "<?php echo 'dummy';";
    $result = ZS_Engine::scanFile('dummy.php', 'dummy.php', $dummyContent, $canonicalKnownHash, $rules, $repoRoot);
    assert_true($result['detected'], 'Engine must flag canonical known hash');
    assert_true(strpos($result['reasons'][0], 'Normalized Hash Match') !== false, 'Detection reason must indicate hash match');
});

// -------------------------------------------------------------
// Test 3: Engine flags malicious patterns
// -------------------------------------------------------------
run_test('Test 3: Engine flags all specified malicious patterns', function() use ($repoRoot) {
    $rules = ZS_Rules::bundled();

    // 1. Nirmala pad literal
    $res1 = ZS_Engine::scanFile('test.php', 'test.php', '<?php /* NIRMALA-HASH-PAD */ ?>', 'hash1', $rules, $repoRoot);
    assert_true($res1['detected'], 'Must flag NIRMALA-HASH-PAD literal');

    // 2. eval(base64_decode(
    $res2 = ZS_Engine::scanFile('test.php', 'test.php', '<?php eval(base64_decode("test")); ?>', 'hash2', $rules, $repoRoot);
    assert_true($res2['detected'], 'Must flag eval(base64_decode(');

    // 3. uploads php
    $res3 = ZS_Engine::scanFile($repoRoot . '/wp-content/uploads/shell.php', 'shell.php', '<?php phpinfo(); ?>', 'hash3', $rules, $repoRoot);
    assert_true($res3['detected'], 'Must flag PHP script in uploads dir');

    // 4. languages non-l10n php
    $res4 = ZS_Engine::scanFile($repoRoot . '/wp-content/languages/bad.php', 'bad.php', '<?php phpinfo(); ?>', 'hash4', $rules, $repoRoot);
    assert_true($res4['detected'], 'Must flag non-l10n PHP in languages dir');

    // 5. double extension
    $res5 = ZS_Engine::scanFile('app.js.php', 'app.js.php', '<?php echo "hi"; ?>', 'hash5', $rules, $repoRoot);
    assert_true($res5['detected'], 'Must flag double extension');

    // 6. rogue core path
    $res6 = ZS_Engine::scanFile($repoRoot . '/wp-includes/SimplePie/src/HTTP/Psr19Client.php', 'Psr19Client.php', '<?php ?>', 'hash6', $rules, $repoRoot);
    assert_true($res6['detected'], 'Must flag rogue core path Psr19Client.php');
});

// -------------------------------------------------------------
// Test 4: Engine does NOT flag benign patterns
// -------------------------------------------------------------
run_test('Test 4: Engine does NOT flag official l10n, uploads index, empty file, or scanner self', function() use ($repoRoot) {
    $rules = ZS_Rules::bundled();

    // 1. Official .l10n.php return-array
    $l10nContent = file_get_contents($repoRoot . '/tests/fixtures/official.l10n.php');
    $res1 = ZS_Engine::scanFile($repoRoot . '/wp-content/languages/en.l10n.php', 'en.l10n.php', $l10nContent, 'hash_l10n', $rules, $repoRoot);
    assert_false($res1['detected'], 'Must NOT flag official WordPress .l10n.php file');

    // 2. uploads/index.php
    $res2 = ZS_Engine::scanFile($repoRoot . '/wp-content/uploads/index.php', 'index.php', '<?php // Silence is golden.', 'hash_idx', $rules, $repoRoot);
    assert_false($res2['detected'], 'Must NOT flag uploads/index.php');

    // 3. empty file
    $res3 = ZS_Engine::scanFile('empty.php', 'empty.php', '', 'hash_empty', $rules, $repoRoot);
    assert_false($res3['detected'], 'Must NOT flag empty file');
});

// -------------------------------------------------------------
// Test 5: 2-strike benign whitelist machine
// -------------------------------------------------------------
run_test('Test 5: 2-strike benign memory machine transitions', function() use ($repoRoot) {
    $tempDir = sys_get_temp_dir() . '/zs_test_strike_' . bin2hex(random_bytes(6));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $hash = 'test_norm_hash_12345';
    $pathA = 'wp-content/plugins/test/a.php';
    $pathB = 'wp-content/plugins/test/b.php';
    $session1 = 'session_alpha';
    $session2 = 'session_beta';

    // First markClean: becomes candidate
    $res1 = $store->markClean($hash, $pathA, $session1);
    assert_equals('candidate_added', $res1['status'], 'First strike must add to candidates');
    assert_false($store->isTrusted($hash), 'Must not be trusted after 1 strike');
    $cand = $store->getCandidate($hash);
    assert_true($cand !== null && $cand['clean_count'] === 1, 'Candidate clean_count must be 1');

    // Second markClean with SAME path and SAME session: stays candidate!
    $res2 = $store->markClean($hash, $pathA, $session1);
    assert_equals('candidate_already_recorded', $res2['status'], 'Same path and session must NOT promote to trusted');
    assert_false($store->isTrusted($hash), 'Must remain untrusted');

    // Strike 2 with DIFFERENT path in same session: promoted to trusted!
    $res3 = $store->markClean($hash, $pathB, $session1);
    assert_equals('promoted_to_trusted', $res3['status'], 'Different path must promote to trusted');
    assert_true($store->isTrusted($hash), 'Must be trusted after second strike on different path');

    // Test strike 2 on same path but DIFFERENT session for another hash
    $hash2 = 'test_norm_hash_67890';
    $store->markClean($hash2, $pathA, $session1);
    $res4 = $store->markClean($hash2, $pathA, $session2);
    assert_equals('promoted_to_trusted', $res4['status'], 'Same path across different sessions must promote to trusted');
    assert_true($store->isTrusted($hash2), 'Hash 2 must be trusted');

    // Cleanup
    @unlink($store->getKnowledgeFile());
    @unlink($store->getSessionFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Test 6: Reset helper deletes session, keeps knowledge
// -------------------------------------------------------------
run_test('Test 6: Reset wipes session file only; knowledge file remains', function() {
    $tempDir = sys_get_temp_dir() . '/zs_test_reset_' . bin2hex(random_bytes(6));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $session = $store->initSession('/var/www', false);
    $store->saveKnowledge(array('schema_version' => 1, 'trusted' => array('h1' => true)));

    assert_true(file_exists($store->getSessionFile()), 'Session file must exist');
    assert_true(file_exists($store->getKnowledgeFile()), 'Knowledge file must exist');

    $store->resetSession();

    assert_false(file_exists($store->getSessionFile()), 'Session file must be deleted on reset');
    assert_true(file_exists($store->getKnowledgeFile()), 'Knowledge file must remain intact on reset');

    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Test 7: Gemini cache key versioning & hit/miss
// -------------------------------------------------------------
run_test('Test 7: Gemini versioned cache hit avoids HTTP, changed model/prompt misses', function() {
    $tempDir = sys_get_temp_dir() . '/zs_test_cache_' . bin2hex(random_bytes(6));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $config = array(
        'gemini_api_keys'   => array('AIzaFakeKey123'),
        'gemini_model'      => 'gemini-flash-latest',
        'ai_prompt_version' => 'prompt_v1',
    );

    $normHash = 'norm_hash_test_777';
    $cacheKey = ZS_Gemini::getCacheKey($normHash, 'gemini-flash-latest', 'prompt_v1', 'rules_v1');

    // Seed cache
    $cachedVerdict = array(
        'verdict'            => 'benign',
        'confidence'         => 0.99,
        'malware_family'     => '',
        'summary'            => 'Pre-cached clean verdict',
        'recommended_action' => 'keep',
    );
    $store->setAiCache($cacheKey, $cachedVerdict);

    // Set HTTP hook to fail if called
    $httpCalled = false;
    ZS_Gemini::$http = function() use (&$httpCalled) {
        $httpCalled = true;
        throw new Exception('HTTP hook called unexpectedly on cache hit!');
    };

    $result = ZS_Gemini::ask($normHash, 'test.php', '<?php harmless();', array(), $config, $store, 'rules_v1');
    assert_true(!empty($result['cache_hit']), 'Must return cache hit');
    assert_equals('benign', $result['verdict'], 'Verdict must match seeded cache');
    assert_false($httpCalled, 'HTTP hook must NOT be called on cache hit');

    // Change model: must miss cache and invoke HTTP hook
    $configChangedModel = $config;
    $configChangedModel['gemini_model'] = 'gemini-1.5-pro';

    ZS_Gemini::$http = function() use (&$httpCalled) {
        $httpCalled = true;
        return array(
            'status' => 200,
            'body'   => json_encode(array(
                'candidates' => array(
                    array(
                        'content' => array(
                            'parts' => array(
                                array(
                                    'text' => json_encode(array(
                                        'verdict'            => 'malicious',
                                        'confidence'         => 0.95,
                                        'summary'            => 'Fresh verdict from new model',
                                        'recommended_action' => 'quarantine',
                                    ))
                                )
                            )
                        )
                    )
                )
            ))
        );
    };

    $res2 = ZS_Gemini::ask($normHash, 'test.php', '<?php harmless();', array(), $configChangedModel, $store, 'rules_v1');
    assert_true($httpCalled, 'HTTP hook MUST be invoked when model changes');
    assert_false(!empty($res2['cache_hit']), 'Cache hit must be false for new model');
    assert_equals('malicious', $res2['verdict'], 'New verdict must be returned');

    ZS_Gemini::$http = null; // reset hook
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Test 8: Auto-review decision matrix
// -------------------------------------------------------------
run_test('Test 8: Auto-review decision matrix quarantines only high-confidence malicious', function() {
    $matrix = array(
        array('verdict' => 'malicious', 'conf' => 0.90, 'action' => 'quarantine', 'shouldDelete' => true),
        array('verdict' => 'benign',    'conf' => 0.90, 'action' => 'keep',       'shouldDelete' => false),
        array('verdict' => 'uncertain', 'conf' => 0.50, 'action' => 'manual_review','shouldDelete' => false),
        array('verdict' => 'malicious', 'conf' => 0.50, 'action' => 'quarantine', 'shouldDelete' => false),
    );

    foreach ($matrix as $case) {
        $isMalicious = ($case['verdict'] === 'malicious');
        $isHighConf  = ($case['conf'] >= 0.85);
        $isQuarantine = ($case['action'] === 'quarantine');
        $decision = ($isMalicious && $isHighConf && $isQuarantine);

        assert_equals($case['shouldDelete'], $decision, "Matrix case failed for " . json_encode($case));
    }
});

// -------------------------------------------------------------
// Test 9: Share anonymizer removes root and DB credentials
// -------------------------------------------------------------
run_test('Test 9: Share anonymizer strips root paths and DB credentials', function() {
    $mockRoot = '/var/www/vhosts/client_site.com/httpdocs';
    $mockFilePath = $mockRoot . '/wp-content/plugins/suspicious/payload.php';

    $rel = ZS_Share::anonymizePath($mockFilePath, $mockRoot);
    assert_equals('wp-content/plugins/suspicious/payload.php', $rel, 'Must strip mock root prefix');

    $mockContent = "<?php\ndefine('DB_PASSWORD', 'super_secret_db_pass_999');\n\$db_password = 'another_secret';\neval(\$_POST['cmd']);\n";
    $evidence = ZS_Share::extractEvidenceLines($mockContent, 10, $mockRoot);

    assert_false(strpos($evidence, 'super_secret_db_pass_999') !== false, 'DB_PASSWORD value must be redacted');
    assert_false(strpos($evidence, 'another_secret') !== false, 'Direct password assignment must be redacted');
    assert_true(strpos($evidence, '[REDACTED]') !== false, 'Must replace credentials with [REDACTED]');
});

// -------------------------------------------------------------
// Test 10: Concurrent auto-review requests locking
// -------------------------------------------------------------
run_test('Test 10: Concurrent auto-review claim lock prevents race conditions', function() {
    $tempDir = sys_get_temp_dir() . '/zs_test_lock_' . bin2hex(random_bytes(6));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $session = $store->initSession('/var/www', true);
    $session['infected_files'] = array(
        array(
            'path'        => '/var/www/test1.php',
            'reason'      => 'Test finding',
            'size'        => 100,
            'status'      => 'FOUND',
            'raw_sha256'  => 'raw1',
            'norm_sha256' => 'norm1',
        )
    );
    $store->saveSession($session);

    $claim1 = $store->claimNextInfectedForAutoReview();
    assert_true($claim1 !== null, 'Process 1 must successfully claim finding');
    assert_equals(0, $claim1['index'], 'Process 1 must claim index 0');

    $claim2 = $store->claimNextInfectedForAutoReview();
    assert_true($claim2 === null, 'Process 2 must get null because finding is already claimed');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Test 11: Maintainer report endpoint consent and validation
// -------------------------------------------------------------
run_test('Test 11: Maintainer endpoint uploads only with explicit consent and valid URL', function() {
    $bundle = array('tool' => 'ZeroShell', 'items' => array());

    // 1. Without consent: must reject
    $res1 = ZS_Share::submitToMaintainer($bundle, 'https://maintainer.example.com/api', false);
    assert_false($res1['success'], 'Must reject when consent is false');

    // 2. With empty endpoint: must reject
    $res2 = ZS_Share::submitToMaintainer($bundle, '', true);
    assert_false($res2['success'], 'Must reject when endpoint is empty');

    // 3. With HTTP instead of HTTPS: must reject
    $res3 = ZS_Share::submitToMaintainer($bundle, 'http://insecure.example.com/api', true);
    assert_false($res3['success'], 'Must reject non-HTTPS endpoint');

    // 4. With HTTPS and consent + mock HTTP: succeeds
    $httpCalled = false;
    ZS_Gemini::$http = function($url, $headers, $body) use (&$httpCalled) {
        $httpCalled = true;
        return array('status' => 200, 'body' => 'OK_RECEIPT_123');
    };

    $res4 = ZS_Share::submitToMaintainer($bundle, 'https://maintainer.example.com/api', true);
    assert_true($res4['success'], 'Must succeed with consent and HTTPS');
    assert_true($httpCalled, 'HTTP hook must be called on maintainer submit');

    ZS_Gemini::$http = null;
});

// -------------------------------------------------------------
// Test 12: php -l on built artifact
// -------------------------------------------------------------
run_test('Test 12: Lint check (php -l) on built malware-cleaner.php', function() use ($repoRoot) {
    $builtFile = $repoRoot . '/malware-cleaner.php';
    assert_true(file_exists($builtFile), 'Built malware-cleaner.php must exist');
    exec('php -l ' . escapeshellarg($builtFile), $out, $code);
    assert_equals(0, $code, 'php -l must return exit code 0');
});

// -------------------------------------------------------------
// Test 13: i18n completeness between en and fa
// -------------------------------------------------------------
run_test('Test 13: i18n completeness: every key in fa.php exists in en.php', function() use ($repoRoot) {
    $en = include $repoRoot . '/src/i18n/en.php';
    $fa = include $repoRoot . '/src/i18n/fa.php';

    assert_true(is_array($en) && !empty($en), 'en.php must be non-empty array');
    assert_true(is_array($fa) && !empty($fa), 'fa.php must be non-empty array');

    $missingInEn = array();
    foreach ($fa as $k => $v) {
        if (!array_key_exists($k, $en)) {
            $missingInEn[] = $k;
        }
    }
    assert_true(empty($missingInEn), 'Keys in fa.php missing in en.php: ' . implode(', ', $missingInEn));

    $missingInFa = array();
    foreach ($en as $k => $v) {
        if (!array_key_exists($k, $fa)) {
            $missingInFa[] = $k;
        }
    }
    assert_true(empty($missingInFa), 'Keys in en.php missing in fa.php: ' . implode(', ', $missingInFa));
});

// -------------------------------------------------------------
// Test 14: Built file contains zero 'nikamooz' strings
// -------------------------------------------------------------
run_test('Test 14: Built malware-cleaner.php contains zero occurrences of nikamooz', function() use ($repoRoot) {
    $builtFile = $repoRoot . '/malware-cleaner.php';
    $content = file_get_contents($builtFile);
    $count = substr_count(strtolower($content), 'nikamooz');
    assert_equals(0, $count, 'Found ' . $count . ' occurrences of nikamooz in built artifact');
});

// -------------------------------------------------------------
// Test 15: Conflict transition: candidate status revoked on malicious/delete
// -------------------------------------------------------------
run_test('Test 15: Conflict transition: candidate status revoked on malicious/delete', function() {
    $tempDir = sys_get_temp_dir() . '/zs_test_conflict_' . bin2hex(random_bytes(6));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $hash = 'candidate_conflict_hash';
    $path = 'wp-content/plugins/bad/shell.php';
    $sessionId = 'session_1';

    // Strike 1: added as candidate
    $store->markClean($hash, $path, $sessionId);
    assert_true($store->getCandidate($hash) !== null, 'Candidate must exist after first strike');

    // Revoke candidate (simulating deletion or high-confidence malicious verdict)
    $revoked = $store->revokeCandidate($hash);
    assert_true($revoked, 'revokeCandidate must return true when candidate existed');
    assert_true($store->getCandidate($hash) === null, 'Candidate must be removed after revocation');

    // Second strike on a different path should now start as strike 1 again (not strike 2)
    $res = $store->markClean($hash, 'wp-content/plugins/bad/shell2.php', $sessionId);
    assert_equals('candidate_added', $res['status'], 'Post-revocation strike must be candidate_added (1 of 2), not trusted');
    assert_false($store->isTrusted($hash), 'Must not be trusted');

    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Test 16: Path jail prevents prefix collision
// -------------------------------------------------------------
run_test('Test 16: Path jail prevents prefix collision (e.g. site_backup vs site)', function() {
    $baseTemp = sys_get_temp_dir() . '/zs_jail_' . bin2hex(random_bytes(4));
    $jailRoot = $baseTemp . '_site';
    $jailSibling = $baseTemp . '_site_backup';

    @mkdir($jailRoot, 0755, true);
    @mkdir($jailSibling, 0755, true);

    $insideFile = $jailRoot . '/legit.php';
    $outsideFile = $jailSibling . '/escaped.php';
    file_put_contents($insideFile, '<?php // inside');
    file_put_contents($outsideFile, '<?php // outside');

    assert_true(ZS_Config::isPathWithinRoot($insideFile, $jailRoot), 'Path inside root must be allowed');
    assert_false(ZS_Config::isPathWithinRoot($outsideFile, $jailRoot), 'Path in sibling with matching prefix must be rejected');

    $qDir = $jailRoot . '/quarantine';
    $res = ZS_Quarantine::copyThenUnlink($outsideFile, $jailRoot, $qDir);
    assert_false($res['success'], 'Quarantine copyThenUnlink must refuse target outside root jail');

    @unlink($insideFile);
    @unlink($outsideFile);
    @rmdir($jailRoot);
    @rmdir($jailSibling);
});

// -------------------------------------------------------------
// Test 17: Gemini 400 schema error retries once with snake_case
// -------------------------------------------------------------
run_test('Test 17: Gemini 400 schema error retries once with snake_case', function() {
    $tempDir = sys_get_temp_dir() . '/zs_test_gemini_retry_' . bin2hex(random_bytes(6));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $config = array(
        'gemini_api_keys'   => array('AIzaFakeRetryKey'),
        'gemini_model'      => 'gemini-flash-latest',
        'ai_prompt_version' => 'prompt_v1',
    );

    $callCount = 0;
    $snakeCaseUsedOnRetry = false;

    ZS_Gemini::$http = function($url, $headers, $payloadJson) use (&$callCount, &$snakeCaseUsedOnRetry) {
        $callCount++;
        $decoded = json_decode($payloadJson, true);

        if ($callCount === 1) {
            // First call uses camelCase generationConfig; simulate Google 400 schema error
            return array(
                'status' => 400,
                'body'   => json_encode(array(
                    'error' => array(
                        'code'    => 400,
                        'message' => "Invalid argument: unknown field 'responseMimeType' in generationConfig",
                        'status'  => 'INVALID_ARGUMENT'
                    )
                ))
            );
        }

        if ($callCount === 2) {
            // Second call: verify snake_case was used
            if (isset($decoded['generation_config']['response_mime_type']) && isset($decoded['generation_config']['response_schema'])) {
                $snakeCaseUsedOnRetry = true;
            }

            return array(
                'status' => 200,
                'body'   => json_encode(array(
                    'candidates' => array(
                        array(
                            'content' => array(
                                'parts' => array(
                                    array(
                                        'text' => json_encode(array(
                                            'verdict'            => 'malicious',
                                            'confidence'         => 0.95,
                                            'malware_family'     => 'webshell',
                                            'summary'            => 'Recovered on snake_case retry',
                                            'recommended_action' => 'quarantine',
                                        ))
                                    )
                                )
                            )
                        )
                    )
                ))
            );
        }

        throw new Exception('Too many HTTP calls in retry test');
    };

    $verdict = ZS_Gemini::ask('norm_hash_retry_test', 'test.php', '<?php shell();', array(), $config, $store, 'rules_v1');
    assert_equals(2, $callCount, 'Gemini ask must retry exactly once on schema error');
    assert_true($snakeCaseUsedOnRetry, 'Retry must supply snake_case schema fields');
    assert_equals('malicious', $verdict['verdict'], 'Verdict must parse successfully after retry');

    ZS_Gemini::$http = null;
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Test 18: Engine path normalization with backslashes and relative paths
// -------------------------------------------------------------
run_test('Test 18: Engine path normalization with backslashes and relative paths', function() use ($repoRoot) {
    $rules = ZS_Rules::bundled();

    // 1. Windows backslashes in uploads path
    $winPath = 'C:\\inetpub\\wordpress\\wp-content\\uploads\\trojan.php';
    $winRoot = 'C:\\inetpub\\wordpress';
    $res1 = ZS_Engine::scanFile($winPath, 'trojan.php', '<?php echo 1;', 'h_win', $rules, $winRoot);
    assert_true($res1['detected'], 'Engine must detect uploads php on Windows path with backslashes');

    // 2. Relative uploads path without root prefix
    $relPath = 'wp-content/uploads/evil.php';
    $res2 = ZS_Engine::scanFile($relPath, 'evil.php', '<?php echo 1;', 'h_rel', $rules, $repoRoot);
    assert_true($res2['detected'], 'Engine must detect relative uploads path');

    // 3. Double extension check
    $doubleExt = 'style.css.php';
    $res3 = ZS_Engine::scanFile($doubleExt, $doubleExt, '<?php echo 1;', 'h_dbl', $rules, $repoRoot);
    assert_true($res3['detected'], 'Engine must detect double extension .css.php');
});

// -------------------------------------------------------------
// Test 19: Restore path jail (no mkdir/write outside root)
// -------------------------------------------------------------
run_test('Test 19: Restore refuses destinations outside root jail', function() {
    $base = sys_get_temp_dir() . '/zs_restore_' . bin2hex(random_bytes(4));
    $root = $base . '/site';
    $outside = $base . '/outside';
    @mkdir($root, 0755, true);
    @mkdir($outside, 0755, true);

    $qDir = $root . '/quarantine';
    $victim = $root . '/plugin.php';
    file_put_contents($victim, '<?php echo 1;');

    $res = ZS_Quarantine::copyThenUnlink($victim, $root, $qDir);
    assert_true($res['success'], 'Setup quarantine must succeed');
    $bName = $res['backup_name'];

    $manifest = ZS_Quarantine::getManifest($qDir);
    $manifest[$bName]['original_path'] = $root . '/../outside/pwned.php';
    file_put_contents($qDir . '/manifest.json', json_encode($manifest));

    $restore = ZS_Quarantine::restore($bName, $root, $qDir);
    assert_false($restore['success'], 'Restore must reject .. traversal outside root');
    assert_false(file_exists($outside . '/pwned.php'), 'Must not write a file outside the jail');

    @unlink($qDir . '/' . $bName);
    @unlink($qDir . '/manifest.json');
    @unlink($qDir . '/.htaccess');
    @unlink($qDir . '/index.php');
    @rmdir($qDir);
    @rmdir($root);
    @rmdir($outside);
    @rmdir($base);
});

// -------------------------------------------------------------
// Test 20: Data directory prefers wp-content when present
// -------------------------------------------------------------
run_test('Test 20: getDataDir uses wp-content when it exists, else site-local dir', function() {
    $base = sys_get_temp_dir() . '/zs_datadir_' . bin2hex(random_bytes(4));
    $withWp = $base . '/wp';
    $withoutWp = $base . '/plain';
    @mkdir($withWp . '/wp-content', 0755, true);
    @mkdir($withoutWp, 0755, true);

    putenv('MALWARE_CLEANER_DATA_DIR');
    $dir1 = ZS_Config::getDataDir($withWp);
    assert_equals($withWp . '/wp-content/malware_cleaner_data', $dir1, 'WP sites must store data under wp-content');

    $dir2 = ZS_Config::getDataDir($withoutWp);
    assert_equals($withoutWp . '/malware_cleaner_data', $dir2, 'Non-WP roots must not jump to the parent directory');

    @rmdir($withWp . '/wp-content');
    @rmdir($withWp);
    @rmdir($withoutWp);
    @rmdir($base);
});

// -------------------------------------------------------------
// Test 21: Client JS parses
// -------------------------------------------------------------
run_test('Test 21: src/assets/app.js is syntactically valid', function() use ($repoRoot) {
    $js = $repoRoot . '/src/assets/app.js';
    assert_true(file_exists($js), 'app.js missing');
    $bin = trim((string)shell_exec('command -v node'));
    if ($bin === '') {
        $src = file_get_contents($js);
        assert_false(strpos($src, "}\n    } else if (key === 'c'") !== false, 'Regression: extra brace before else if in keydown handler');
        return;
    }
    exec('node --check ' . escapeshellarg($js), $out, $code);
    assert_equals(0, $code, 'node --check must pass for app.js: ' . implode("\n", $out));
});

// -------------------------------------------------------------
// Test 22: Stale AI_PROCESSING claims can be retried
// -------------------------------------------------------------
run_test('Test 22: Stale AI_PROCESSING items are reclaimable after timeout', function() {
    $tempDir = sys_get_temp_dir() . '/zs_test_stale_' . bin2hex(random_bytes(6));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $session = $store->initSession('/var/www', true);
    $session['infected_files'] = array(
        array(
            'path'          => '/var/www/stuck.php',
            'reason'        => 'Test',
            'size'          => 10,
            'status'        => 'AI_PROCESSING',
            'ai_claimed_at' => time() - 120,
            'raw_sha256'    => 'raw',
            'norm_sha256'   => 'norm',
        )
    );
    $store->saveSession($session);

    $claim = $store->claimNextInfectedForAutoReview();
    assert_true($claim !== null, 'Stale AI_PROCESSING row must be reclaimable');
    assert_equals(0, $claim['index'], 'Must reclaim index 0');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Summary
// -------------------------------------------------------------
echo "\n===================================\n";
echo "Test Results: {$testsPassed} passed, {$testsFailed} failed.\n";
echo "===================================\n";

if ($testsFailed > 0) {
    exit(1);
}
exit(0);
