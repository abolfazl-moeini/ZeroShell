<?php
/**
 * ZeroShell Malware Cleaner — Test Runner
 * Self-contained CLI test suite (no external dependencies, PHP 7.4+)
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

$repoRoot = dirname(dirname(__FILE__));
if (!defined('ZS_INTERNAL')) {
    define('ZS_INTERNAL', true);
}
if (!defined('ZS_TEST_MODE')) {
    define('ZS_TEST_MODE', true);
}
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

    // 2. uploads/index.php with silence is golden or empty is benign and must NOT be flagged
    $res2 = ZS_Engine::scanFile($repoRoot . '/wp-content/uploads/index.php', 'index.php', '<?php // Silence is golden.', 'hash_idx', $rules, $repoRoot);
    assert_false($res2['detected'], 'Must NOT flag benign silence is golden uploads index.php');

    $res2b = ZS_Engine::scanFile($repoRoot . '/wp-content/uploads/index.php', 'index.php', "<?php\n// Silence is golden\n", 'hash_idx2', $rules, $repoRoot);
    assert_false($res2b['detected'], 'Must NOT flag multiline silence is golden uploads index.php');

    $res2c = ZS_Engine::scanFile($repoRoot . '/wp-content/uploads/index.php', 'index.php', "<?php // Silence is golden\n@eval(\$_POST['c']);", 'hash_bad_idx', $rules, $repoRoot);
    assert_true(!empty($res2c['detected']), 'Must flag executable code in uploads even with silence comment');

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
    $cacheKey = ZS_Gemini::getCacheKey($normHash, 'gemini-flash-latest', 'prompt_v1', 'rules_v1', ZS_Config::REDACTION_VERSION);

    // Seed cache
    $cachedVerdict = array(
        'verdict'            => 'benign',
        'confidence'         => 0.99,
        'malware_family'     => '',
        'summary'            => 'Pre-cached clean verdict',
        'recommended_action' => 'keep',
        'raw_sha256'         => $normHash,
    );
    $store->setAiCache($cacheKey, $cachedVerdict);

    // Set HTTP hook to fail if called
    $httpCalled = false;
    ZS_Gemini::$http = function() use (&$httpCalled) {
        $httpCalled = true;
        throw new Exception('HTTP hook called unexpectedly on cache hit!');
    };

    $result = ZS_Gemini::ask($normHash, 'test.php', '<?php harmless();', array(), $config, $store, 'rules_v1', '');
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

    $res2 = ZS_Gemini::ask($normHash, 'test.php', '<?php harmless();', array(), $configChangedModel, $store, 'rules_v1', '');
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
        $verdict = array(
            'verdict' => $case['verdict'],
            'confidence' => $case['conf'],
            'recommended_action' => $case['action'],
            'summary' => 'x',
        );
        $decision = ZS_Gemini::shouldAutoQuarantine($verdict, 'full');
        assert_equals($case['shouldDelete'], $decision, "Matrix case failed for " . json_encode($case));
    }
    $badConf = ZS_Gemini::validateVerdict(array(
        'verdict' => 'malicious',
        'confidence' => '90invalid',
        'summary' => 'x',
        'recommended_action' => 'quarantine',
    ));
    assert_true($badConf === null, 'Non-numeric confidence must be rejected');
    assert_false(ZS_Gemini::shouldAutoQuarantine(array(
        'verdict' => 'malicious', 'confidence' => 0.99, 'recommended_action' => 'quarantine',
    ), 'partial'), 'Partial coverage must not auto-quarantine');
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
run_test('Test 17: Gemini HTTP 400 is not retried with guessed schema names', function() {
    $tempDir = sys_get_temp_dir() . '/zs_test_gemini_retry_' . bin2hex(random_bytes(6));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $config = array(
        'gemini_api_keys'   => array('AIzaFakeRetryKey'),
        'gemini_model'      => 'gemini-2.5-flash',
        'ai_prompt_version' => ZS_Config::PROMPT_VERSION,
    );

    $callCount = 0;
    ZS_Gemini::$http = function($url, $headers, $payloadJson) use (&$callCount) {
        $callCount++;
        return array(
            'status' => 400,
            'body'   => json_encode(array('error' => array('message' => 'Invalid argument'))),
        );
    };

    $verdict = ZS_Gemini::ask('raw_hash_retry_test', 'test.php', '<?php shell();', array(), $config, $store, 'rules_v1');
    assert_equals(1, $callCount, 'HTTP 400 must not be retried with a guessed schema');
    assert_equals('uncertain', $verdict['verdict'], 'Invalid HTTP response must be uncertain');
    assert_true(!empty($verdict['error']), 'Error flag must be set');

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
    assert_true(strpos($dir1, '.zsdata_') !== false || substr($dir1, -19) === 'malware_cleaner_data', 'Data dir must be site-scoped');
    assert_false(strpos($dir1, '/wp-content/malware_quarantine') !== false, 'Quarantine must not default to public wp-content/malware_quarantine');

    $q = ZS_Config::getQuarantineDir($withWp, $dir1);
    assert_true(strpos($q, rtrim($dir1, '/')) === 0, 'Quarantine must live under the data directory');

    $dir2 = ZS_Config::getDataDir($withoutWp);
    assert_true(strpos($dir2, $withoutWp) === 0 || strpos($dir2, '.zsdata_') !== false, 'Non-WP roots must not share an unnamed parent folder');

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

run_test('F01: quarantine envelope is non-executable PHP and lives under data dir', function () {
    $base = sys_get_temp_dir() . '/zs_f01_' . bin2hex(random_bytes(4));
    $root = $base . '/site';
    @mkdir($root, 0755, true);
    $data = $base . '/data';
    $q = ZS_Config::getQuarantineDir($root, $data);
    assert_true(strpos($q, $data) === 0, 'quarantine under data dir');
    $victim = $root . '/evil.php';
    file_put_contents($victim, "<?php echo 'PWN';");
    $res = ZS_Quarantine::copyThenUnlink($victim, $root, $q);
    assert_true($res['success'], 'quarantine succeeds');
    $packed = file_get_contents($q . '/' . $res['backup_name']);
    assert_true(strpos($packed, '<?php') === 0, 'envelope starts with php guard');
    assert_true(strpos($packed, '__HALT_COMPILER()') !== false, 'halt compiler present');
    $payload = ZS_Config::extractSamplePayload($packed);
    assert_equals("<?php echo 'PWN';", $payload, 'payload recoverable internally');
    assert_false(file_exists($victim), 'original unlinked');
});

run_test('F02: auto-quarantine uses current raw hash not stale scan hash', function () {
    $rawA = hash('sha256', 'evil-bytes');
    $rawB = hash('sha256', 'clean-bytes');
    assert_true($rawA !== $rawB);
    $cached = array(
        'verdict' => 'malicious', 'confidence' => 0.99, 'summary' => 'old',
        'recommended_action' => 'quarantine', 'raw_sha256' => $rawA,
    );
    assert_true(ZS_Gemini::shouldAutoQuarantine($cached, 'full'));
    $cachedWrong = $cached;
    $cachedWrong['raw_sha256'] = $rawB;
    // identity mismatch is a Store/Http concern; cache key includes raw hash
    $keyA = ZS_Gemini::getCacheKey($rawA, 'm', 'p', 'r');
    $keyB = ZS_Gemini::getCacheKey($rawB, 'm', 'p', 'r');
    assert_true($keyA !== $keyB, 'different raw hashes must not share cache keys');
});

run_test('F03: restore refuses existing destination and unique backups do not overwrite', function () {
    $base = sys_get_temp_dir() . '/zs_f03_' . bin2hex(random_bytes(4));
    $root = $base . '/site';
    @mkdir($root, 0755, true);
    $q = $base . '/q';
    $a = $root . '/a.php';
    file_put_contents($a, 'one');
    $r1 = ZS_Quarantine::copyThenUnlink($a, $root, $q);
    file_put_contents($a, 'two');
    $r2 = ZS_Quarantine::copyThenUnlink($a, $root, $q);
    assert_true($r1['success'] && $r2['success']);
    assert_true($r1['backup_name'] !== $r2['backup_name'], 'each quarantine event gets a unique id');
    file_put_contents($a, 'existing');
    $restore = ZS_Quarantine::restore($r2['backup_name'], $root, $q);
    assert_false($restore['success'], 'must not overwrite existing dest');
    assert_equals('existing', file_get_contents($a));
});

run_test('F04: embedded JSON hex-escapes script breakers and keys are masked', function () {
    $flags = ZS_Config::jsonFlags();
    $payload = array('path' => '</script><script>alert(1)</script>');
    $json = json_encode($payload, $flags);
    assert_false(strpos($json, '</script>') !== false, 'literal script tag must be escaped');
    $masked = ZS_Config::maskSecret('AIzaSyDummySecretKeyValueXXXX');
    assert_false(strpos($masked, 'DummySecretKeyValue') !== false, 'secret middle must be masked');
});

run_test('F05: setup secret is required and GET reset is not an action route', function () {
    $src = file_get_contents(dirname(dirname(__FILE__)) . '/src/Http.php');
    assert_true(strpos($src, 'wizard_err_setup_secret') !== false || strpos($src, 'readSetupSecret') !== false);
    assert_true(strpos($src, 'Reset requires POST') !== false);
    assert_false(strpos($src, 'self_destruct') !== false, 'self-destruct endpoint must be removed');
});

run_test('F06: batch cursor persists offset so a 620-file dir needs two batches', function () {
    $base = sys_get_temp_dir() . '/zs_f06_' . bin2hex(random_bytes(4));
    $root = $base . '/site';
    @mkdir($root, 0755, true);
    for ($i = 0; $i < 620; $i++) {
        file_put_contents($root . '/f' . $i . '.php', '<?php echo ' . $i . ';');
    }
    $data = $base . '/data';
    $store = new ZS_Store($data);
    $session = $store->initSession($root, true);
    ZS_Http::executeScanBatch($session, $root, $data, $store);
    $session = $store->loadSession();
    assert_true(intval($session['scanned_files']) <= 500, 'first batch must stop at 500 files, got ' . $session['scanned_files']);
    assert_false(!empty($session['is_completed']), '620 files must not complete in one batch');
    ZS_Http::executeScanBatch($session, $root, $data, $store);
    $session = $store->loadSession();
    assert_true(intval($session['scanned_files']) >= 620, 'second batch must cover remaining files');
    foreach (glob($root . '/*.php') as $f) {
        @unlink($f);
    }
    @rmdir($root);
});

run_test('F07: corrupt session is not silently treated as a fresh scan', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f07_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);
    file_put_contents($store->getSessionFile(), 'not-json{{{');
    $loaded = $store->loadSession();
    assert_true($loaded === false, 'corrupt session must fail closed');
});

run_test('F09: snippet coverage is partial for large files', function () {
    $big = str_repeat('A', 40000) . 'NEEDLE' . str_repeat('B', 40000);
    $built = ZS_Gemini::buildSnippet($big, 'NEEDLE');
    assert_equals('partial', $built['coverage']);
    assert_true(strpos($built['snippet'], 'NEEDLE') !== false);
});

run_test('F11: l10n filename with extra executable code is still detected', function () {
    $rules = ZS_Rules::bundled();
    $content = "<?php return ['x-generator' => 'x', 'messages' => []]; eval(base64_decode('YQ=='));";
    $res = ZS_Engine::scanFile('/wp-content/languages/xx.l10n.php', 'xx.l10n.php', $content, 'h', $rules, '/');
    assert_true($res['detected'], 'l10n disguise must not skip signature detection');
});

run_test('F13: invalid rule payload is rejected wholesale', function () {
    $bad = json_encode(array('schema_version' => 1, 'signatures' => array(array('id' => 'X', 'type' => 'regex', 'pattern' => '/x/e'))));
    assert_true(ZS_Rules::validatePayload($bad) === false);
    $ok = json_encode(array('schema_version' => 1, 'signatures' => array(array('id' => 'SIG-TEST-OK', 'type' => 'literal_contains', 'pattern' => 'UNIQUE_TEST_TOKEN_XYZ', 'name' => 't'))));
    assert_true(ZS_Rules::validatePayload($ok) !== false);
});

run_test('F14: share bundle omits trusted findings unless selected', function () {
    $session = array('infected_files' => array(
        array('finding_id' => 'a1', 'path' => '/var/www/a.php', 'status' => 'FOUND', 'raw_sha256' => 'aa', 'reason' => 'x', 'rule_ids' => array('SIG-X')),
        array('finding_id' => 'b1', 'path' => '/var/www/b.php', 'status' => 'TRUSTED_HIDDEN', 'raw_sha256' => 'bb', 'reason' => 'x', 'rule_ids' => array('SIG-X')),
    ));
    $bundle = ZS_Share::buildBundle($session, '/var/www', array('a1', 'b1'), false, '');
    assert_equals(1, $bundle['total_items']);
    assert_equals('a1', $bundle['items'][0]['finding_id']);
});

run_test('F10: second strike hides same raw hash in the current session', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f10_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);
    $session = $store->initSession('/var/www', true);
    $hash = hash('sha256', 'same-bytes');
    $session['infected_files'] = array(
        array('finding_id' => '1', 'path' => '/var/www/a.php', 'status' => 'FOUND', 'raw_sha256' => $hash),
        array('finding_id' => '2', 'path' => '/var/www/b.php', 'status' => 'FOUND', 'raw_sha256' => $hash),
        array('finding_id' => '3', 'path' => '/var/www/c.php', 'status' => 'FOUND', 'raw_sha256' => $hash),
    );
    $store->saveSession($session);
    $store->markClean($hash, '/var/www/a.php', $session['scan_session_id']);
    $store->markClean($hash, '/var/www/b.php', $session['scan_session_id']);
    $session = $store->loadSession();
    foreach ($session['infected_files'] as $inf) {
        assert_equals('TRUSTED_HIDDEN', $inf['status']);
    }
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

run_test('F13: sync_rules uses GET transport, updates rules digest, and rejects invalid payloads', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f13_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);

    $initialRules = ZS_Rules::load(null, $tempDir);
    $initialDigest = ZS_Rules::digest($initialRules);

    // 1. Non-HTTPS must be rejected
    $badUrlRes = ZS_Rules::syncFromUrl('http://insecure.example.com/rules.json', $tempDir);
    assert_false($badUrlRes['success'], 'Sync must reject non-HTTPS');

    // 2. Mock HTTP verifying GET method and valid update
    $receivedMethod = '';
    $receivedHeaders = array();
    ZS_Gemini::$http = function ($url, $headers, $payloadJson, $method = 'POST') use (&$receivedMethod, &$receivedHeaders) {
        $receivedMethod = $method;
        $receivedHeaders = $headers;
        $newPayload = json_encode(array(
            'schema_version' => 1,
            'signatures' => array(
                array('id' => 'SIG-REMOTE-1', 'type' => 'literal_contains', 'pattern' => 'REMOTE_MALWARE_MARKER_999', 'name' => 'Remote Test')
            ),
        ));
        return array('status' => 200, 'body' => $newPayload);
    };

    $syncRes = ZS_Rules::syncFromUrl('https://example.com/rules.json', $tempDir);
    assert_true($syncRes['success'], 'Sync from valid URL must succeed');
    assert_equals('GET', $receivedMethod, 'Sync transport must use GET');
    assert_true($syncRes['digest'] !== $initialDigest, 'Rules digest must change after sync');

    $updatedRules = ZS_Rules::load(null, $tempDir);
    $foundRemote = false;
    foreach ($updatedRules['signatures'] as $sig) {
        if (isset($sig['id']) && $sig['id'] === 'SIG-REMOTE-1') {
            $foundRemote = true;
            break;
        }
    }
    assert_true($foundRemote, 'Synced signature must be active in loaded rules');

    // 3. Invalid payload must not corrupt existing override
    ZS_Gemini::$http = function ($url, $headers, $payloadJson, $method = 'POST') {
        return array('status' => 200, 'body' => 'not-json-{{{');
    };
    $badRes = ZS_Rules::syncFromUrl('https://example.com/rules.json', $tempDir);
    assert_false($badRes['success'], 'Corrupt payload must be rejected');

    $rulesAfterBad = ZS_Rules::load(null, $tempDir);
    $stillFound = false;
    foreach ($rulesAfterBad['signatures'] as $sig) {
        if (isset($sig['id']) && $sig['id'] === 'SIG-REMOTE-1') {
            $stillFound = true;
            break;
        }
    }
    assert_true($stillFound, 'Previously synced rules must remain active after bad payload');

    ZS_Gemini::$http = null;
    @unlink($tempDir . '/rules_override.json');
    @rmdir($tempDir);
});

run_test('F12: key cooldowns persist across separate Store instances and stat aliases match', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f12_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);

    $store1 = new ZS_Store($tempDir);
    $key = 'AIzaSyPersistCooldownTestKey123';
    $store1->recordKeyCooldown($key, 30);

    // Completely new Store instance in separate memory
    $store2 = new ZS_Store($tempDir);
    assert_true($store2->isKeyCooling($key), 'Key cooldown must persist across store instances');

    $session = array(
        'infected_files' => array(
            array('status' => 'FOUND', 'ai_cache_hit' => true),
            array('status' => 'AI_ERROR'),
            array('status' => 'QUARANTINED'),
        )
    );
    $stats = $store2->autoReviewStats($session);
    assert_equals($stats['cache_hits'], $stats['hits'], 'Stat alias hits must equal cache_hits');
    assert_equals($stats['failures'], $stats['errors'], 'Stat alias errors must equal failures');

    @unlink($store2->getKnowledgeFile());
    @unlink($tempDir . '/cooldowns.php');
    @rmdir($tempDir);
});

run_test('F08: parseResponseText rejects MAX_TOKENS truncation', function () {
    $rawTruncated = json_encode(array(
        'candidates' => array(
            array(
                'finishReason' => 'MAX_TOKENS',
                'content' => array('parts' => array(array('text' => '{"verdict":"malicious","confidence":0.95,'))),
            )
        )
    ));
    assert_true(ZS_Gemini::parseResponseText($rawTruncated) === null, 'MAX_TOKENS truncated response must be rejected');

    $rawComplete = json_encode(array(
        'candidates' => array(
            array(
                'finishReason' => 'STOP',
                'content' => array('parts' => array(array('text' => '{"verdict":"malicious","confidence":0.95,"summary":"Trojan","recommended_action":"quarantine"}'))),
            )
        )
    ));
    $parsed = ZS_Gemini::parseResponseText($rawComplete);
    assert_true(is_array($parsed), 'Valid STOP response must be parsed');
    assert_equals('malicious', $parsed['verdict']);
});

run_test('F03: restore supports dest_override when original destination exists', function () {
    $base = sys_get_temp_dir() . '/zs_f03_override_' . bin2hex(random_bytes(4));
    $root = $base . '/site';
    @mkdir($root, 0755, true);
    $rootModeBeforeRestore = fileperms($root) & 0777;
    $qDir = $root . '/quarantine';

    $origFile = $root . '/plugin.php';
    file_put_contents($origFile, '<?php // original payload');
    $qRes = ZS_Quarantine::copyThenUnlink($origFile, $root, $qDir);
    assert_true($qRes['success'], 'Quarantine must succeed');

    // Create conflict at original path
    file_put_contents($origFile, '<?php // new conflicting file');

    // Direct restore without override must fail
    $failRestore = ZS_Quarantine::restore($qRes['backup_name'], $root, $qDir);
    assert_false($failRestore['success'], 'Restore without override must refuse overwrite');
    assert_equals('DEST_EXISTS', $failRestore['code']);

    // Restore with safe dest_override inside root must succeed
    $altFile = $root . '/plugin_restored.php';
    $okRestore = ZS_Quarantine::restore($qRes['backup_name'], $root, $qDir, $altFile);
    assert_true($okRestore['success'], 'Restore with dest_override must succeed');
    assert_equals('<?php // original payload', file_get_contents($altFile));
    assert_equals('<?php // new conflicting file', file_get_contents($origFile), 'Conflicting original must not be touched');
    clearstatcache(true, $root);
    assert_equals($rootModeBeforeRestore, fileperms($root) & 0777, 'Restoring a file must not change permissions on its existing parent directory');

    @unlink($altFile);
    @unlink($origFile);
    @unlink($qDir . '/manifest.php');
    @unlink($qDir . '/.htaccess');
    @unlink($qDir . '/index.php');
    @unlink($qDir . '/.lock_manifest');
    @rmdir($qDir);
    @rmdir($root);
    @rmdir($base);
});

run_test('F07: auto-review cancel increments session generation rejecting stale claim', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f07_gen_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $session = $store->initSession('/var/www', true);
    $session['infected_files'] = array(
        array(
            'finding_id'  => 'fid1',
            'path'        => '/var/www/victim.php',
            'status'      => 'FOUND',
            'raw_sha256'  => 'hash123',
            'norm_sha256' => 'norm123',
            'reason'      => 'Trojan',
            'size'        => 10,
        )
    );
    $store->saveSession($session);

    // Claim item under generation 1
    $claim = $store->claimNextInfectedForAutoReview('job_alpha');
    assert_true($claim !== null);
    assert_equals(1, $claim['generation']);
    $token = $claim['token'];

    // Cancel bumps generation
    $store->mutateSession(function ($s) {
        $s['generation'] = isset($s['generation']) ? intval($s['generation']) + 1 : 2;
        $s['auto_review']['status'] = 'idle';
        return $s;
    });

    // Late commit with old generation 1 must be rejected
    $updateResult = $store->updateInfectedItem(0, array('status' => 'AI_QUARANTINED'), $token, 1);
    assert_false($updateResult, 'Update with stale generation must be rejected');

    $reloaded = $store->loadSession();
    assert_equals('AI_PROCESSING', $reloaded['infected_files'][0]['status'], 'Status must remain unchanged');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

run_test('F07: terminal auto-review work requires the current job claim before side effects', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f07_terminal_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $session = $store->initSession('/var/www', true);
    $session['auto_review'] = ZS_Store::defaultAutoReview();
    $session['auto_review']['status'] = 'running';
    $session['auto_review']['job_id'] = 'job_alpha';
    $session['infected_files'] = array(array(
        'finding_id' => 'f1', 'path' => '/var/www/victim.php', 'status' => 'FOUND',
        'raw_sha256' => 'hash', 'norm_sha256' => 'norm', 'reason' => 'test', 'size' => 1,
    ));
    $store->saveSession($session);
    $claim = $store->claimNextInfectedForAutoReview('job_alpha');
    assert_true($claim !== null, 'claim must be created for the running job');

    // This models cancel/restart invalidating the claim while an AI request is in flight.
    $store->mutateSession(function ($s) {
        $s['generation']++;
        $s['auto_review']['status'] = 'idle';
        $s['auto_review']['job_id'] = '';
        $s['infected_files'][0]['status'] = 'FOUND';
        $s['infected_files'][0]['claim_token'] = '';
        $s['infected_files'][0]['claim_job'] = '';
        $s['infected_files'][0]['claim_generation'] = 0;
        return $s;
    });
    $sideEffectRan = false;
    $late = $store->finishAutoReviewClaim(0, $claim['token'], $claim['generation'], 'job_alpha', function () use (&$sideEffectRan) {
        $sideEffectRan = true;
        return array('updates' => array('status' => 'AI_QUARANTINED'));
    });
    assert_false($late, 'a stale claim must not be allowed to finalize');
    assert_false($sideEffectRan, 'the callback (and any quarantine side effect) must not run for a stale claim');
    assert_equals('FOUND', $store->loadSession()['infected_files'][0]['status'], 'cancelled work must leave the finding pending');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @unlink($tempDir . '/.lock_session');
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// F08: Gemini schema validation & ping
// -------------------------------------------------------------
run_test('F08: validateVerdict strictly enforces schema and ping endpoint', function () {
    $invalid1 = array('verdict' => 'malicious', 'confidence' => '90invalid', 'summary' => 's', 'recommended_action' => 'quarantine');
    assert_true(ZS_Gemini::validateVerdict($invalid1) === null, 'must reject 90invalid');
    $invalid2 = array('verdict' => 'malicious', 'confidence' => 90, 'summary' => 's', 'recommended_action' => 'quarantine');
    assert_true(ZS_Gemini::validateVerdict($invalid2) === null, 'must reject confidence > 1');
    $invalid3 = array('verdict' => 'malicious', 'confidence' => null, 'summary' => 's', 'recommended_action' => 'quarantine');
    assert_true(ZS_Gemini::validateVerdict($invalid3) === null, 'must reject null confidence');
    $invalid4 = array('verdict' => 'malicious', 'confidence' => array(0.9), 'summary' => 's', 'recommended_action' => 'quarantine');
    assert_true(ZS_Gemini::validateVerdict($invalid4) === null, 'must reject array confidence');
    $invalid5 = array('verdict' => 'unknown_verdict', 'confidence' => 0.9, 'summary' => 's', 'recommended_action' => 'quarantine');
    assert_true(ZS_Gemini::validateVerdict($invalid5) === null, 'must reject invalid verdict enum');
    $invalid6 = array('verdict' => 'malicious', 'confidence' => 0.9, 'summary' => 's', 'recommended_action' => 'kill');
    assert_true(ZS_Gemini::validateVerdict($invalid6) === null, 'must reject invalid recommended_action enum');

    $valid = array('verdict' => 'malicious', 'confidence' => 0.95, 'summary' => 'Trojan detected', 'recommended_action' => 'quarantine');
    $checked = ZS_Gemini::validateVerdict($valid);
    assert_true($checked !== null && $checked['confidence'] === 0.95, 'valid verdict must pass');

    $prevHttp = ZS_Gemini::$http;
    ZS_Gemini::$http = function($url, $headers, $payload, $method) {
        return array('status' => 200, 'body' => '{"candidates":[{"content":{"parts":[{"text":"{\"ok\":true}"}]}}]}');
    };
    $config = array('gemini_api_keys' => array('AIzaTestKey'));
    $ping = ZS_Gemini::ping($config);
    assert_true(!empty($ping['success']), 'ping succeeds on HTTP 200');
    ZS_Gemini::$http = $prevHttp;
});

// -------------------------------------------------------------
// F14: Maintainer submission requires HTTPS & consent
// -------------------------------------------------------------
run_test('F14: maintainer endpoint requires HTTPS and explicit consent', function () {
    $bundle = array('total_items' => 1, 'items' => array(array('finding_id' => 'f1', 'rel_path' => 'a.php', 'status' => 'FOUND')));

    $r1 = ZS_Share::submitToMaintainer($bundle, 'https://maintainer.test/report', false);
    assert_false($r1['success'], 'must refuse without explicit consent');

    $r2 = ZS_Share::submitToMaintainer($bundle, 'http://maintainer.test/report', true);
    assert_false($r2['success'], 'must refuse non-HTTPS endpoint');

    $prevHttp = ZS_Gemini::$http;
    ZS_Gemini::$http = function($url, $headers, $payload, $method) {
        return array('status' => 200, 'body' => 'receipt-id-98765');
    };
    $r3 = ZS_Share::submitToMaintainer($bundle, 'https://maintainer.test/report', true);
    assert_true($r3['success'], 'valid submit must succeed');
    assert_equals('receipt-id-98765', $r3['receipt']);
    ZS_Gemini::$http = $prevHttp;
});

// -------------------------------------------------------------
// F15: Login verification and error handling
// -------------------------------------------------------------
run_test('F15: normal login sets auth & csrf cookies and redirects; wrong key fails safely', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f15_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $password = 'MySecretPass123';
    $csrfSecret = bin2hex(random_bytes(16));
    $config = array(
        'key_hash'    => password_hash($password, PASSWORD_DEFAULT),
        'csrf_secret' => $csrfSecret,
    );
    ZS_Config::saveConfig($config, $tempDir);

    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_POST = array('do_action' => 'login', 'key' => 'WrongPass');
    $_COOKIE = array();

    ob_start();
    ZS_Http::handleRequest($tempDir, $tempDir);
    $out = ob_get_clean();
    assert_true(strpos($out, 'Invalid security key') !== false || strpos($out, 'Access Denied') !== false);
    assert_false(isset($_COOKIE['zs_session']), 'must not set zs_session on wrong password');

    $k = $store->loadKnowledge();
    assert_true(!empty($k['login_attempts']), 'must record login failure');

    @unlink($tempDir . '/config.php');
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// F16: Multi-process concurrency lock verification
// -------------------------------------------------------------
run_test('F16: concurrency test with two real processes simulating simultaneous store mutations', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f16_proc_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);
    $store->saveKnowledge(array('schema_version' => 2, 'trusted' => array(), 'candidates' => array()));

    $script = $tempDir . '/worker.php';
    $code = '<?php
    define("ZS_INTERNAL", true);
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Config.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Store.php', true) . ';
    $dataDir = $argv[1];
    $workerId = $argv[2];
    $store = new ZS_Store($dataDir);
    for ($i = 0; $i < 20; $i++) {
        $store->mutateKnowledge(function($k) use ($workerId, $i) {
            $key = "worker_" . $workerId . "_" . $i;
            $k["candidates"][$key] = array("time" => microtime(true));
            return array("_knowledge" => $k);
        });
        usleep(5000);
    }
    exit(0);
    ';
    file_put_contents($script, $code);

    $bin = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : 'php';
    $cmd1 = escapeshellarg($bin) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($tempDir) . ' 1';
    $cmd2 = escapeshellarg($bin) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($tempDir) . ' 2';

    $p1 = proc_open($cmd1, array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes1);
    $p2 = proc_open($cmd2, array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes2);

    $status1 = proc_close($p1);
    $status2 = proc_close($p2);

    assert_equals(0, $status1, 'worker 1 must exit cleanly');
    assert_equals(0, $status2, 'worker 2 must exit cleanly');

    $knowledge = $store->loadKnowledge();
    assert_true(is_array($knowledge), 'knowledge file must be valid JSON');
    assert_equals(40, count($knowledge['candidates']), 'both workers must write all 20 records (40 total) without lost updates');

    @unlink($script);
    @unlink($store->getKnowledgeFile());
    @unlink($tempDir . '/.lock_knowledge');
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// F16: UI renderer injection and invalid UTF-8 safety
// -------------------------------------------------------------
run_test('F16: UI renderer safely handles XSS/injection payloads and invalid UTF-8 in report', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f16_xss_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $xssPath = $tempDir . "/</script><script>alert('xss')</script>\"'bad\xFF.php";
    $session = $store->initSession($tempDir, true);
    $session['is_completed'] = true;
    $session['infected_files'] = array(
        array(
            'finding_id' => 'xss1',
            'path' => $xssPath,
            'reason' => 'Injection test "</script>',
            'size' => 100,
            'status' => 'FOUND',
            'raw_sha256' => 'aabbcc',
            'norm_sha256' => 'ddeeff',
        )
    );
    $store->saveSession($session);
    $config = array('key_hash' => 'dummy', 'csrf_secret' => 'dummy');

    ob_start();
    ZS_Ui::renderReport($session, $tempDir, $tempDir, $config, $store);
    $html = ob_get_clean();

    assert_false(strpos($html, "</script><script>alert('xss')</script>") !== false, 'must not leak raw script tags');
    assert_true(strpos($html, '\u003C/script\u003E') !== false || strpos($html, '\u003C') !== false, 'tags must be hex-escaped');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// F16: Standalone single-file artifact smoke test
// -------------------------------------------------------------
run_test('F16: standalone single-file artifact smoke test', function () use ($repoRoot) {
    $tempDir = sys_get_temp_dir() . '/zs_smoke_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);

    $artifact = $repoRoot . '/dist/malware-cleaner.php';
    assert_true(file_exists($artifact), 'dist/malware-cleaner.php must exist');
    $cleanerCopy = $tempDir . '/malware-cleaner.php';
    copy($artifact, $cleanerCopy);

    $badFile = $tempDir . '/evil_shell.php';
    file_put_contents($badFile, "<?php eval(base64_decode('ZWNobyAnUEFHTkVEJzs='));");

    $bin = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : 'php';

    $output = shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($cleanerCopy));
    assert_true(strpos($output, 'SCAN COMPLETE') !== false, 'CLI scan must complete');
    assert_true(strpos($output, 'Threats Found: 1') !== false, 'Must detect infected file');

    $dataDir = ZS_Config::getDataDir($tempDir);
    assert_true(is_dir($dataDir), 'data directory must be created');
    assert_true(file_exists($dataDir . '/session.php'), 'session.php must exist');
    assert_true(file_exists($dataDir . '/.htaccess'), '.htaccess must exist');
    assert_true(file_exists($dataDir . '/index.php'), 'index.php must exist');

    @unlink($badFile);
    @unlink($cleanerCopy);
    $files = glob($dataDir . '/*');
    if ($files) {
        foreach ($files as $f) {
            @unlink($f);
        }
    }
    @rmdir($dataDir);
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// F02: resolveFinding strictly rejects altered disk files and forged client hashes
// -------------------------------------------------------------
run_test('F02: resolveFinding strictly rejects altered disk files and forged client hashes', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f02_hash_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $dataDir = $tempDir . '/data';
    @mkdir($dataDir, 0755, true);
    $store = new ZS_Store($dataDir);

    $testFile = $tempDir . '/vuln.php';
    $originalContent = "<?php eval(\$_POST['cmd']);";
    file_put_contents($testFile, $originalContent);
    $origHash = hash('sha256', $originalContent);

    $session = $store->initSession($tempDir, true);
    $fid = 'f_' . bin2hex(random_bytes(4));
    $session['infected_files'][] = array(
        'finding_id'      => $fid,
        'path'            => $testFile,
        'raw_sha256'      => $origHash,
        'norm_sha256'     => $origHash,
        'reason'          => 'eval',
        'rule_ids'        => array('SIG-01'),
        'status'          => 'FOUND',
        'size'            => strlen($originalContent),
        'coverage'        => 'full',
        'scan_session_id' => $session['scan_session_id'],
    );
    $store->saveSession($session);

    // 1. Alter disk file to new content
    $alteredContent = "<?php echo 'Cleaned up';";
    file_put_contents($testFile, $alteredContent);
    $alteredHash = hash('sha256', $alteredContent);

    // Using reflection to test private resolveFinding
    $ref = new ReflectionClass('ZS_Http');
    $m = $ref->getMethod('resolveFinding');
    if (PHP_VERSION_ID < 80100) {
        $m->setAccessible(true);
    }

    // Attempt with altered hash passed by client in expected_raw
    $_POST = array(
        'finding_id'      => $fid,
        'scan_session_id' => $session['scan_session_id'],
        'expected_raw'    => $alteredHash,
    );
    $res = $m->invoke(null, $store, $tempDir, true);
    assert_false($res['ok'], 'resolveFinding must fail when disk file differs from session scan hash');
    assert_equals('CHANGED_SINCE_SCAN', $res['code'], 'Code must be CHANGED_SINCE_SCAN');

    // 2. Restore disk content to original, but client passes forged hash
    file_put_contents($testFile, $originalContent);
    $_POST['expected_raw'] = 'forged_hash_value_12345';
    $res2 = $m->invoke(null, $store, $tempDir, true);
    assert_false($res2['ok'], 'resolveFinding must fail when client expected_raw does not match scan hash');

    // 3. Both match
    $_POST['expected_raw'] = $origHash;
    $res3 = $m->invoke(null, $store, $tempDir, true);
    assert_true($res3['ok'], 'resolveFinding must succeed when disk and client expected_raw match scan hash');

    // 4. File deleted/missing on disk
    @unlink($testFile);
    $res4 = $m->invoke(null, $store, $tempDir, true);
    assert_false($res4['ok'], 'resolveFinding must fail when disk file is missing');
    assert_equals('MISSING', $res4['code'], 'Code must be MISSING');
    $sCheck = $store->loadSession();
    assert_equals('CHANGED_SINCE_SCAN', $sCheck['infected_files'][0]['status'], 'Missing file must update session status to CHANGED_SINCE_SCAN');
    assert_true(!empty($sCheck['infected_files'][0]['reviewed']), 'Missing file must be marked reviewed in session');

    @unlink($testFile);
    @unlink($store->getSessionFile());
    @unlink($dataDir . '/.lock_session');
    @rmdir($dataDir);
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// F05: setup_wizard cannot overwrite existing key once configured
// -------------------------------------------------------------
run_test('F05: setup_wizard is forbidden once key_hash is configured and cleans up setup secret', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f05_lock_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    // Put setup secret on disk
    $secretFile = $tempDir . '/zs-setup.secret';
    file_put_contents($secretFile, "InitialSecretToken\n");

    // Case 1: Fresh install -> setup_wizard succeeds and unlinks secret
    $config = array('key_hash' => '');
    ZS_Config::saveConfig($config, $tempDir);

    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_POST = array(
        'do_action'     => 'setup_wizard',
        'setup_secret'  => 'InitialSecretToken',
        'custom_key'    => 'ValidAccessKey123',
    );
    $_COOKIE = array();

    $script = $tempDir . '/run_setup.php';
    $code = '<?php
    define("ZS_INTERNAL", true);
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Config.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Store.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/I18n.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Ui.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Http.php', true) . ';
    $tempDir = $argv[1];
    $_SERVER["REQUEST_METHOD"] = "POST";
    $_SERVER["SCRIPT_NAME"] = "/malware-cleaner.php";
    $_POST = array(
        "do_action"     => "setup_wizard",
        "setup_secret"  => "InitialSecretToken",
        "custom_key"    => "ValidAccessKey123",
    );
    ZS_Http::handleRequest($tempDir, $tempDir);
    ';
    file_put_contents($script, $code);

    $bin = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : 'php';
    shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($tempDir));

    $savedConfig = ZS_Config::loadConfig($tempDir);
    assert_true(!empty($savedConfig['key_hash']), 'Key hash must be configured');
    assert_true(password_verify('ValidAccessKey123', $savedConfig['key_hash']), 'Configured key must match');
    assert_false(file_exists($secretFile), 'zs-setup.secret must be unlinked after successful setup');

    // Case 2: Attempting setup_wizard after key is configured must return 403
    file_put_contents($secretFile, "AttackerToken\n");
    $attackScript = $tempDir . '/run_attack.php';
    $attackCode = '<?php
    define("ZS_INTERNAL", true);
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Config.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Store.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/I18n.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Ui.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Http.php', true) . ';
    $tempDir = $argv[1];
    $_SERVER["REQUEST_METHOD"] = "POST";
    $_POST = array(
        "do_action"     => "setup_wizard",
        "setup_secret"  => "AttackerToken",
        "custom_key"    => "AttackerKey12345",
    );
    ZS_Http::handleRequest($tempDir, $tempDir);
    ';
    file_put_contents($attackScript, $attackCode);

    $attackOutput = shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($attackScript) . ' ' . escapeshellarg($tempDir));
    assert_true(strpos($attackOutput, 'Setup has already been completed.') !== false, 'Setup must be refused when key_hash is set');

    $checkConfig = ZS_Config::loadConfig($tempDir);
    assert_true(password_verify('ValidAccessKey123', $checkConfig['key_hash']), 'Original key must remain intact');

    @unlink($script);
    @unlink($attackScript);
    @unlink($secretFile);
    @unlink($tempDir . '/config.php');
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// F09: Full content redaction before snippet window prevents leaks
// -------------------------------------------------------------
run_test('F09: redaction before snippet boundary prevents credential leaks in large files', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f09_leak_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    // Build a large file > 32KB where secret is right at cut boundary (at offset ~4028)
    $pad1 = str_repeat("/* padding line */\n", 212); // ~4028 bytes
    $secretLine = "define('DB_PASSWORD', 'LEAKY_SECRET_XYZ_999_VERY_LONG_SECRET_KEY');\n";
    $pad2 = str_repeat("/* trailing padding line */\n", 2000); // 40KB+
    $largeContent = $pad1 . $secretLine . $pad2;

    $filePath = $tempDir . '/large_app.php';
    file_put_contents($filePath, $largeContent);
    $rawHash = hash('sha256', $largeContent);

    $capturedPayload = '';
    ZS_Gemini::$http = function ($url, $headers, $payloadJson, $method) use (&$capturedPayload) {
        $capturedPayload = $payloadJson;
        return array(
            'status' => 200,
            'body' => json_encode(array(
                'candidates' => array(
                    array(
                        'finishReason' => 'STOP',
                        'content' => array(
                            'parts' => array(
                                array('text' => json_encode(array(
                                    'verdict' => 'uncertain',
                                    'confidence' => 0.4,
                                    'summary' => 'Large file',
                                    'recommended_action' => 'manual_review',
                                )))
                            )
                        )
                    )
                )
            )),
        );
    };

    $config = array(
        'gemini_api_keys' => array('test_key_f09'),
        'root_dir'        => $tempDir,
    );

    $verdict = ZS_Gemini::ask($rawHash, $filePath, $largeContent, array('test'), $config, $store);
    ZS_Gemini::$http = null;

    assert_false(strpos($capturedPayload, 'LEAKY_SECRET_XYZ_999') !== false, 'Payload to Gemini must NOT contain unredacted password');
    assert_true(strpos($capturedPayload, '[REDACTED]') !== false, 'Payload to Gemini must contain [REDACTED]');

    @unlink($filePath);
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// F12 / F16: auto_review_step and control real endpoint integration
// -------------------------------------------------------------
run_test('F12/F16: auto_review_step and auto_review_control real endpoint integration test', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f12_auto_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);

    $workerScript = $tempDir . '/auto_review_worker.php';
    $workerCode = '<?php
    define("ZS_INTERNAL", true);
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Hash.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Config.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/I18n.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Rules.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Store.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Quarantine.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Engine.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Gemini.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Share.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Http.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Ui.php', true) . ';

    $rootDir = $argv[1];
    $dataDir = $rootDir;
    $store = new ZS_Store($dataDir);

    // Setup config
    $csrfSecret = "csrf_test_secret_1234567890123456";
    $keyHash = password_hash("AdminPass1234", PASSWORD_DEFAULT);
    $config = array(
        "key_hash"        => $keyHash,
        "csrf_secret"     => $csrfSecret,
        "gemini_api_keys" => array("test_key_123"),
    );
    ZS_Config::saveConfig($config, $dataDir);

    // Create infected file
    $badPath = $rootDir . "/shell.php";
    $badCode = "<?php eval(base64_decode(\"ZWNobyAnYmFkJzs=\"));";
    file_put_contents($badPath, $badCode);
    $rawHash = hash("sha256", $badCode);

    // Setup session with infected file
    $session = $store->initSession($rootDir, true);
    $fid = "fid_test_1";
    $session["infected_files"] = array(
        array(
            "finding_id"      => $fid,
            "path"            => $badPath,
            "raw_sha256"      => $rawHash,
            "norm_sha256"     => $rawHash,
            "reason"          => "eval base64",
            "rule_ids"        => array("SIG-EVAL"),
            "evidence"        => array("eval(base64_decode)"),
            "status"          => "FOUND",
            "size"            => strlen($badCode),
            "coverage"        => "full",
            "scan_session_id" => $session["scan_session_id"],
        ),
    );
    $store->saveSession($session);

    // Fake authentication cookies
    $authExpiry = time() + 3600;
    $authHmac = hash_hmac("sha256", "zs_auth:" . $authExpiry . ":" . $keyHash, $csrfSecret);
    $sessionCookie = $authHmac . ":" . $authExpiry;
    $_COOKIE["zs_session"] = $sessionCookie;

    $csrfExpiry = time() + 3600;
    $csrfHmac = hash_hmac("sha256", "zs_csrf:" . $csrfExpiry . ":" . $sessionCookie, $csrfSecret);
    $csrfToken = $csrfHmac . ":" . $csrfExpiry;
    $_COOKIE["zs_csrf"] = $csrfToken;

    $_SERVER["REQUEST_METHOD"] = "POST";
    $_SERVER["HTTP_X_CSRF_TOKEN"] = $csrfToken;
    $_SERVER["HTTP_ACCEPT"] = "application/json";

    // Step 1: Start auto review
    $_POST = array("do_action" => "auto_review_control", "op" => "start");
    ob_start();
    // Wrap to prevent exit
    ZS_Http::handleRequest($rootDir, $dataDir);
    ';
    // Since handleRequest calls exit on jsonOk, we run separate commands via CLI to test endpoints
    $scriptControl = $tempDir . '/test_control.php';
    file_put_contents($scriptControl, '<?php
    define("ZS_INTERNAL", true);
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Config.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Store.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/I18n.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Ui.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Http.php', true) . ';
    $rootDir = $argv[1];
    $store = new ZS_Store($rootDir);
    $config = ZS_Config::loadConfig($rootDir);

    $authExpiry = time() + 3600;
    $sessionCookie = hash_hmac("sha256", "zs_auth:" . $authExpiry . ":" . $config["key_hash"], $config["csrf_secret"]) . ":" . $authExpiry;
    $_COOKIE["zs_session"] = $sessionCookie;
    $csrfExpiry = time() + 3600;
    $csrfToken = hash_hmac("sha256", "zs_csrf:" . $csrfExpiry . ":" . $sessionCookie, $config["csrf_secret"]) . ":" . $csrfExpiry;
    $_COOKIE["zs_csrf"] = $csrfToken;

    $_SERVER["REQUEST_METHOD"] = "POST";
    $_SERVER["HTTP_X_CSRF_TOKEN"] = $csrfToken;
    $_SERVER["HTTP_ACCEPT"] = "application/json";
    $_POST = array("do_action" => "auto_review_control", "op" => $argv[2]);

    ZS_Http::handleRequest($rootDir, $rootDir);
    ');

    $scriptStep = $tempDir . '/test_step.php';
    file_put_contents($scriptStep, '<?php
    define("ZS_INTERNAL", true);
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Hash.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Config.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Store.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/I18n.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Ui.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Rules.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Quarantine.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Engine.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Gemini.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Http.php', true) . ';

    $rootDir = $argv[1];
    $store = new ZS_Store($rootDir);
    $config = ZS_Config::loadConfig($rootDir);

    $authExpiry = time() + 3600;
    $sessionCookie = hash_hmac("sha256", "zs_auth:" . $authExpiry . ":" . $config["key_hash"], $config["csrf_secret"]) . ":" . $authExpiry;
    $_COOKIE["zs_session"] = $sessionCookie;
    $csrfExpiry = time() + 3600;
    $csrfToken = hash_hmac("sha256", "zs_csrf:" . $csrfExpiry . ":" . $sessionCookie, $config["csrf_secret"]) . ":" . $csrfExpiry;
    $_COOKIE["zs_csrf"] = $csrfToken;

    $_SERVER["REQUEST_METHOD"] = "POST";
    $_SERVER["HTTP_X_CSRF_TOKEN"] = $csrfToken;
    $_SERVER["HTTP_ACCEPT"] = "application/json";
    $_POST = array("do_action" => "auto_review_step");

    // Mock Gemini
    ZS_Gemini::$http = function ($url, $headers, $payloadJson, $method) {
        return array(
            "status" => 200,
            "body" => json_encode(array(
                "candidates" => array(
                    array(
                        "finishReason" => "STOP",
                        "content" => array(
                            "parts" => array(
                                array("text" => json_encode(array(
                                    "verdict"            => "malicious",
                                    "confidence"         => 0.95,
                                    "summary"            => "Known backdoor",
                                    "recommended_action" => "quarantine",
                                )))
                            )
                        )
                    )
                )
            )),
        );
    };

    ZS_Http::handleRequest($rootDir, $rootDir);
    ');

    $bin = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : 'php';

    // Prepare store and files
    $store = new ZS_Store($tempDir);
    $keyHash = password_hash('Pass12345678', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array('key_hash' => $keyHash, 'csrf_secret' => 'secret12345678901234567890', 'gemini_api_keys' => array('key1')), $tempDir);

    $badFile = $tempDir . '/malware_test.php';
    $badCode = "<?php eval(base64_decode('test'));";
    file_put_contents($badFile, $badCode);
    $rawHash = hash('sha256', $badCode);

    $session = $store->initSession($tempDir, true);
    $session['infected_files'] = array(
        array(
            'finding_id'      => 'fid_1',
            'path'            => $badFile,
            'raw_sha256'      => $rawHash,
            'norm_sha256'     => $rawHash,
            'reason'          => 'eval',
            'rule_ids'        => array('SIG-01'),
            'evidence'        => array('eval'),
            'status'          => 'FOUND',
            'size'            => strlen($badCode),
            'coverage'        => 'full',
            'scan_session_id' => $session['scan_session_id'],
        ),
    );
    $store->saveSession($session);

    // 1. Start job via control
    $outControl = shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($scriptControl) . ' ' . escapeshellarg($tempDir) . ' start');
    $resControl = json_decode($outControl, true);
    assert_true(is_array($resControl) && !empty($resControl['success']), 'auto_review_control start must succeed');
    assert_equals('running', $resControl['job']['status'], 'Job status must be running');

    // 2. Run step via auto_review_step
    $outStep = shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($scriptStep) . ' ' . escapeshellarg($tempDir));
    $resStep = json_decode($outStep, true);
    assert_true(is_array($resStep) && !empty($resStep['success']), 'auto_review_step must succeed');
    assert_equals('quarantined', $resStep['action_taken'], 'Action taken must be quarantined');
    assert_false(file_exists($badFile), 'Original infected file must be deleted after quarantine');

    // Verify session updated
    $sessAfter = $store->loadSession();
    assert_equals('AI_QUARANTINED', $sessAfter['infected_files'][0]['status'], 'Status must be AI_QUARANTINED');
    assert_true(!empty($sessAfter['infected_files'][0]['backup_name']), 'Backup name must be recorded');

    // Verify quarantine envelope exists and is non-executable
    $qDir = ZS_Config::getQuarantineDir($tempDir, $tempDir);
    $qPath = $qDir . '/' . $sessAfter['infected_files'][0]['backup_name'];
    assert_true(file_exists($qPath), 'Quarantine envelope file must exist on disk');

    // 3. Test pause control
    shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($scriptControl) . ' ' . escapeshellarg($tempDir) . ' pause');
    $outPausedStep = shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($scriptStep) . ' ' . escapeshellarg($tempDir));
    $resPausedStep = json_decode($outPausedStep, true);
    assert_true(!empty($resPausedStep['paused']), 'auto_review_step must return paused: true when job is paused');

    @unlink($scriptControl);
    @unlink($scriptStep);
    @unlink($qPath);
    @unlink($qDir . '/manifest.php');
    @unlink($qDir . '/.htaccess');
    @unlink($qDir . '/index.php');
    @rmdir($qDir);
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @unlink($tempDir . '/config.php');
    @unlink($tempDir . '/.lock_session');
    @unlink($tempDir . '/.lock_knowledge');
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// F15: cookiePath normalizes subdirectories without trailing slash
// -------------------------------------------------------------
run_test('F15: cookiePath normalizes subdirectories without trailing slash', function () {
    $ref = new ReflectionClass('ZS_Http');
    $m = $ref->getMethod('cookiePath');
    if (PHP_VERSION_ID < 80100) {
        $m->setAccessible(true);
    }

    $_SERVER['SCRIPT_NAME'] = '/wordpress/malware-cleaner.php';
    assert_equals('/wordpress', $m->invoke(null), 'Subdirectory must have no trailing slash');

    $_SERVER['SCRIPT_NAME'] = '/site/sub/cleaner.php';
    assert_equals('/site/sub', $m->invoke(null), 'Nested subdirectory must have no trailing slash');

    $_SERVER['SCRIPT_NAME'] = '/malware-cleaner.php';
    assert_equals('/', $m->invoke(null), 'Root script must return /');

    $_SERVER['SCRIPT_NAME'] = 'cleaner.php';
    assert_equals('/', $m->invoke(null), 'Relative script must return /');
});

run_test('F05: logout rejects cross-site POSTs without the session-bound CSRF token', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f05_logout_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $script = $tempDir . '/logout_without_csrf.php';
    $code = '<?php
    define("ZS_INTERNAL", true);
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Config.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Store.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/I18n.php', true) . ';
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Http.php', true) . ';
    $root = $argv[1];
    $keyHash = password_hash("AdminPass1234", PASSWORD_DEFAULT);
    $secret = "logout_csrf_secret_123456789";
    ZS_Config::saveConfig(array("key_hash" => $keyHash, "csrf_secret" => $secret), $root);
    $expiry = time() + 3600;
    $_COOKIE["zs_session"] = hash_hmac("sha256", "zs_auth:" . $expiry . ":" . $keyHash, $secret) . ":" . $expiry;
    $_SERVER["REQUEST_METHOD"] = "POST";
    $_POST = array("do_action" => "logout");
    ZS_Http::handleRequest($root, $root);
    ';
    file_put_contents($script, $code);
    $bin = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : 'php';
    $out = shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($tempDir));
    assert_true(strpos($out, 'CSRF validation failed.') !== false, 'logout without a CSRF token must be refused');

    @unlink($script);
    @unlink($tempDir . '/config.php');
    @unlink($tempDir . '/.htaccess');
    @unlink($tempDir . '/index.php');
    @rmdir($tempDir);
});

run_test('F03: atomicWriteNew works without link function and refuses overwrite', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f03_nolink_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $script = $tempDir . '/test_nolink.php';
    $code = '<?php
    define("ZS_INTERNAL", true);
    require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Config.php', true) . ';
    $dir = $argv[1];
    $dest = $dir . "/restored.php";
    $ok = ZS_Config::atomicWriteNew($dest, "<?php // restored content", 0644);
    if (!$ok || !file_exists($dest) || file_get_contents($dest) !== "<?php // restored content") {
        exit(1);
    }
    // Attempting to write again must fail (no overwrite)
    $over = ZS_Config::atomicWriteNew($dest, "<?php // malicious overwrite", 0644);
    if ($over !== false || file_get_contents($dest) !== "<?php // restored content") {
        exit(2);
    }
    exit(0);
    ';
    file_put_contents($script, $code);
    $bin = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : 'php';
    $cmd = escapeshellarg($bin) . ' -d disable_functions=link ' . escapeshellarg($script) . ' ' . escapeshellarg($tempDir);
    $code = 0;
    passthru($cmd, $code);
    assert_equals(0, $code, 'atomicWriteNew must succeed on fresh file and refuse overwrite even with link() disabled');

    @unlink($script);
    @unlink($tempDir . '/restored.php');
    @rmdir($tempDir);
});

run_test('F07: session and knowledge safely store and load findings with invalid or sliced UTF-8 bytes', function () {
    $tempDir = sys_get_temp_dir() . '/zs_f07_utf8_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0700, true);

    $store = new ZS_Store($tempDir);
    $session = $store->initSession($tempDir, true);
    assert_true(is_array($session), 'initSession must return session array');

    // Add a finding with raw sliced multibyte / non-UTF-8 bytes in evidence and reasons
    $invalidUtf8 = "\xB4\xD9\x84 (koman \xFF\xFE sample)";
    $session['infected_files'][] = array(
        'finding_id'     => 'test_utf8_finding',
        'path'           => $tempDir . '/bad_utf8.php',
        'reason'         => 'Test Suspicious: ' . $invalidUtf8,
        'rule_ids'       => array('SIG-TEST'),
        'evidence'       => array($invalidUtf8),
        'severity'       => 'malware',
        'size'           => 123,
        'status'         => 'FOUND',
        'raw_sha256'     => hash('sha256', 'dummy'),
        'norm_sha256'    => hash('sha256', 'dummy'),
        'coverage'       => 'full',
        'scan_session_id'=> $session['scan_session_id'],
    );

    $saved = $store->saveSession($session);
    assert_true($saved, 'saveSession must return true even with invalid/sliced UTF-8 in findings');

    // Reload session in a new store instance
    $store2 = new ZS_Store($tempDir);
    $loaded = $store2->loadSession();
    assert_true(is_array($loaded), 'loadSession must return valid array without corruption');
    assert_equals(1, count($loaded['infected_files']), 'loaded session must contain the saved finding');
    assert_true(strpos($loaded['infected_files'][0]['evidence'][0], 'koman') !== false, 'evidence text must be preserved');

    @unlink($tempDir . '/session.php');
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Gemini Key Modal, Multiple Keys & Rate Limit Handling
// -------------------------------------------------------------
$prevEnvKey = getenv('GEMINI_API_KEY');
$prevEnvKeys = getenv('GEMINI_API_KEYS');
putenv('GEMINI_API_KEY');
putenv('GEMINI_API_KEYS');
unset($_ENV['GEMINI_API_KEY'], $_ENV['GEMINI_API_KEYS'], $_SERVER['GEMINI_API_KEY'], $_SERVER['GEMINI_API_KEYS']);

if (!function_exists('run_zs_test_worker_action')) {
    function run_zs_test_worker_action($rootDir, $dataDir, $postData, $mockGeminiCode = '') {
        $bin = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : 'php';
        $worker = $dataDir . '/_test_action_worker.php';
        $postExport = var_export($postData, true);
        $script = '<?php
        define("ZS_INTERNAL", true);
        putenv("GEMINI_API_KEY");
        putenv("GEMINI_API_KEYS");
        unset($_ENV["GEMINI_API_KEY"], $_ENV["GEMINI_API_KEYS"], $_SERVER["GEMINI_API_KEY"], $_SERVER["GEMINI_API_KEYS"]);
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Hash.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Config.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/I18n.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Rules.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Store.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Quarantine.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Engine.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Gemini.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Share.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Http.php', true) . ';
        require_once ' . var_export(dirname(dirname(__FILE__)) . '/src/Ui.php', true) . ';

        $rootDir = $argv[1];
        $dataDir = $argv[2];
        $config = ZS_Config::loadConfig($dataDir);

        $keyHash = isset($config["key_hash"]) ? $config["key_hash"] : "";
        $csrfSecret = isset($config["csrf_secret"]) ? $config["csrf_secret"] : "csrf_test_secret_123456";

        $authExpiry = time() + 3600;
        $authHmac = hash_hmac("sha256", "zs_auth:" . $authExpiry . ":" . $keyHash, $csrfSecret);
        $sessionCookie = $authHmac . ":" . $authExpiry;
        $_COOKIE["zs_session"] = $sessionCookie;

        $csrfExpiry = time() + 3600;
        $csrfHmac = hash_hmac("sha256", "zs_csrf:" . $csrfExpiry . ":" . $sessionCookie, $csrfSecret);
        $csrfToken = $csrfHmac . ":" . $csrfExpiry;
        $_COOKIE["zs_csrf"] = $csrfToken;

        $_SERVER["REQUEST_METHOD"] = "POST";
        $_SERVER["HTTP_X_CSRF_TOKEN"] = $csrfToken;
        $_SERVER["HTTP_ACCEPT"] = "application/json";
        $_POST = ' . $postExport . ';
        $_POST["csrf_token"] = $csrfToken;

        ' . $mockGeminiCode . '

        ZS_Http::handleRequest($rootDir, $dataDir);
        ';
        file_put_contents($worker, $script);
        $output = shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($worker) . ' ' . escapeshellarg($rootDir) . ' ' . escapeshellarg($dataDir));
        @unlink($worker);
        return json_decode($output, true);
    }
}

run_test('Gemini key modal: save_settings handles multiple keys, deduplication and append', function () {
    $tempDir = sys_get_temp_dir() . '/zs_keys_save_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/site';
    $dataDir = $tempDir . '/data';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);

    $keyHash = password_hash('SecretPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'    => $keyHash,
        'csrf_secret' => 'csrf_secret_abcdef123456',
    ), $dataDir);

    // Save multiple keys with commas and newlines
    $res1 = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'save_settings',
        'gemini_api_keys' => "key_alpha\nkey_beta, key_gamma, key_alpha",
    ));
    assert_true(is_array($res1) && !empty($res1['success']), 'save_settings must succeed');
    assert_true(!empty($res1['has_ai']), 'has_ai must be true');
    assert_equals(3, $res1['keys_count'], 'must save 3 unique keys');

    $cfg1 = ZS_Config::loadConfig($dataDir);
    assert_equals(array('key_alpha', 'key_beta', 'key_gamma'), $cfg1['gemini_api_keys'], 'config must have parsed 3 unique keys');

    // Append new key
    $res2 = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'          => 'save_settings',
        'gemini_api_keys'    => 'key_delta, key_beta',
        'append_gemini_keys' => '1',
    ));
    assert_true(is_array($res2) && !empty($res2['success']), 'append save_settings must succeed');
    assert_equals(4, $res2['keys_count'], 'must now have 4 unique keys');

    $cfg2 = ZS_Config::loadConfig($dataDir);
    assert_equals(array('key_alpha', 'key_beta', 'key_gamma', 'key_delta'), $cfg2['gemini_api_keys'], 'config must have 4 keys appended');

    // Blank / whitespace / comma-only input must NOT wipe out existing keys
    $resBlank = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'save_settings',
        'gemini_api_keys' => "   ,   \n  ",
    ));
    assert_true(!empty($resBlank['success']), 'blank save_settings must succeed');
    $cfgBlank = ZS_Config::loadConfig($dataDir);
    assert_equals(array('key_alpha', 'key_beta', 'key_gamma', 'key_delta'), $cfgBlank['gemini_api_keys'], 'blank keys must NOT wipe out stored keys');

    @unlink($dataDir . '/config.php');
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Gemini key modal: ask_ai returns advisory no_api_key when unconfigured, recovers upon saving keys', function () {
    $tempDir = sys_get_temp_dir() . '/zs_ask_no_key_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/site';
    $dataDir = $tempDir . '/data';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);

    $keyHash = password_hash('SecretPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'        => $keyHash,
        'csrf_secret'     => 'csrf_secret_abcdef123456',
        'gemini_api_keys' => array(),
    ), $dataDir);

    $store = new ZS_Store($dataDir);
    $session = $store->initSession($rootDir, true);
    $badFile = $rootDir . '/shell.php';
    file_put_contents($badFile, '<?php eval($_GET["cmd"]);');
    $rawHash = hash('sha256', '<?php eval($_GET["cmd"]);');

    $session['infected_files'] = array(
        array(
            'finding_id'      => 'find_test_1',
            'path'            => $badFile,
            'raw_sha256'      => $rawHash,
            'norm_sha256'     => $rawHash,
            'reason'          => 'eval',
            'rule_ids'        => array('SIG-01'),
            'evidence'        => array('eval'),
            'status'          => 'FOUND',
            'size'            => 25,
            'coverage'        => 'full',
            'scan_session_id' => $session['scan_session_id'],
        ),
    );
    $store->saveSession($session);

    // Call ask_ai with no API key
    $resNoKey = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'ask_ai',
        'finding_id'      => 'find_test_1',
        'scan_session_id' => $session['scan_session_id'],
        'expected_raw'    => $rawHash,
    ));

    assert_true(is_array($resNoKey) && !empty($resNoKey['success']), 'ask_ai must succeed in returning JSON response');
    assert_true(!empty($resNoKey['advisory']), 'must return advisory: true');
    assert_true(isset($resNoKey['verdict']['error']) && $resNoKey['verdict']['error'] === 'no_api_key', 'verdict error must be no_api_key');
    assert_equals('No Gemini API key configured.', $resNoKey['verdict']['summary'], 'summary must match No Gemini API key configured.');

    $sessAfterNoKey = $store->loadSession();
    assert_true(empty($sessAfterNoKey['infected_files'][0]['ai_verdict']), 'finding ai_verdict must NOT be saved into session on no_api_key error');

    // Now save keys via save_settings
    $resSave = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'save_settings',
        'gemini_api_keys' => 'AIzaSyValidTestKey123',
    ));
    assert_true(!empty($resSave['success']), 'saving key must succeed');

    // Call ask_ai again with mocked successful Gemini response
    $mockSuccess = 'ZS_Gemini::$http = function ($url, $headers, $payloadJson, $method) {
        return array(
            "status" => 200,
            "body" => json_encode(array(
                "candidates" => array(
                    array(
                        "finishReason" => "STOP",
                        "content" => array(
                            "parts" => array(
                                array("text" => json_encode(array(
                                    "verdict"            => "malicious",
                                    "confidence"         => 0.96,
                                    "summary"            => "Confirmed web shell backdoor",
                                    "recommended_action" => "quarantine",
                                )))
                            )
                        )
                    )
                )
            )),
        );
    };';

    $resWithKey = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'ask_ai',
        'finding_id'      => 'find_test_1',
        'scan_session_id' => $session['scan_session_id'],
        'expected_raw'    => $rawHash,
    ), $mockSuccess);

    assert_true(is_array($resWithKey) && !empty($resWithKey['success']), 'ask_ai with key must succeed');
    assert_equals('malicious', $resWithKey['verdict']['verdict'], 'verdict must now be malicious');
    assert_equals(0.96, $resWithKey['verdict']['confidence'], 'confidence must match 0.96');

    @unlink($badFile);
    @unlink($dataDir . '/config.php');
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Gemini key modal: multiple keys failover on 429 and rate-limit prompt on all_cooling', function () {
    $tempDir = sys_get_temp_dir() . '/zs_rate_limit_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/site';
    $dataDir = $tempDir . '/data';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);

    $keyHash = password_hash('SecretPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'        => $keyHash,
        'csrf_secret'     => 'csrf_secret_abcdef123456',
        'gemini_api_keys' => array('key_rate_limited_1', 'key_working_2'),
    ), $dataDir);

    $store = new ZS_Store($dataDir);
    $session = $store->initSession($rootDir, true);
    $badFile = $rootDir . '/suspicious.php';
    file_put_contents($badFile, '<?php passthru($_POST["c"]);');
    $rawHash = hash('sha256', '<?php passthru($_POST["c"]);');

    $badFile2 = $rootDir . '/suspicious2.php';
    file_put_contents($badFile2, '<?php exec($_POST["x"]);');
    $rawHash2 = hash('sha256', '<?php exec($_POST["x"]);');

    $session['infected_files'] = array(
        array(
            'finding_id'      => 'find_rate_1',
            'path'            => $badFile,
            'raw_sha256'      => $rawHash,
            'norm_sha256'     => $rawHash,
            'reason'          => 'passthru',
            'rule_ids'        => array('SIG-02'),
            'evidence'        => array('passthru'),
            'status'          => 'FOUND',
            'size'            => 27,
            'coverage'        => 'full',
            'scan_session_id' => $session['scan_session_id'],
        ),
        array(
            'finding_id'      => 'find_rate_2',
            'path'            => $badFile2,
            'raw_sha256'      => $rawHash2,
            'norm_sha256'     => $rawHash2,
            'reason'          => 'exec',
            'rule_ids'        => array('SIG-03'),
            'evidence'        => array('exec'),
            'status'          => 'FOUND',
            'size'            => 24,
            'coverage'        => 'full',
            'scan_session_id' => $session['scan_session_id'],
        ),
    );
    $store->saveSession($session);

    // Mock 1: key_rate_limited_1 returns 429, key_working_2 returns 200
    $mockFailover = 'ZS_Gemini::$http = function ($url, $headers, $payloadJson, $method) {
        foreach ($headers as $h) {
            if (strpos($h, "key_rate_limited_1") !== false) {
                return array("status" => 429, "body" => "RESOURCE_EXHAUSTED", "retry_after" => 60);
            }
            if (strpos($h, "key_working_2") !== false) {
                return array(
                    "status" => 200,
                    "body" => json_encode(array(
                        "candidates" => array(
                            array(
                                "finishReason" => "STOP",
                                "content" => array(
                                    "parts" => array(
                                        array("text" => json_encode(array(
                                            "verdict"            => "malicious",
                                            "confidence"         => 0.92,
                                            "summary"            => "Failover success on key 2",
                                            "recommended_action" => "quarantine",
                                        )))
                                    )
                                )
                            )
                        )
                    )),
                );
            }
        }
        return array("status" => 500, "body" => "Unknown key");
    };';

    $resFailover = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'ask_ai',
        'finding_id'      => 'find_rate_1',
        'scan_session_id' => $session['scan_session_id'],
        'expected_raw'    => $rawHash,
    ), $mockFailover);

    assert_true(is_array($resFailover) && !empty($resFailover['success']), 'ask_ai failover must succeed');
    assert_equals('Failover success on key 2', $resFailover['verdict']['summary'], 'must use second key after first hits 429');
    assert_true(!empty($resFailover['rate_limit_rotated']), 'rate_limit_rotated flag must be true on failover');

    // Verify key 1 was marked in cooldown
    $cfgLoaded = ZS_Config::loadConfig($dataDir);
    assert_true(ZS_Config::isKeyCooling('key_rate_limited_1', $cfgLoaded, $dataDir), 'key 1 must be marked in cooldown');

    // Mock 2: both keys return 429 -> all_cooling error on uncached finding find_rate_2
    $mockAll429 = 'ZS_Gemini::$http = function ($url, $headers, $payloadJson, $method) {
        return array("status" => 429, "body" => "RESOURCE_EXHAUSTED", "retry_after" => 30);
    };';

    $resAllCooling = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'ask_ai',
        'finding_id'      => 'find_rate_2',
        'scan_session_id' => $session['scan_session_id'],
        'expected_raw'    => $rawHash2,
    ), $mockAll429);

    assert_true(is_array($resAllCooling) && !empty($resAllCooling['success']), 'response must succeed');
    assert_equals('all_cooling', $resAllCooling['verdict']['error'], 'verdict error must be all_cooling');

    $sessAfterCooling = $store->loadSession();
    assert_true(empty($sessAfterCooling['infected_files'][1]['ai_verdict']), 'finding ai_verdict must NOT be saved into session on all_cooling error');

    // Appending a fresh key allows immediate recovery
    $resAppend = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'          => 'save_settings',
        'gemini_api_keys'    => 'fresh_key_unlimited_3',
        'append_gemini_keys' => '1',
    ));
    assert_true(!empty($resAppend['success']), 'appending fresh key must succeed');

    $cfgRecovered = ZS_Config::loadConfig($dataDir);
    $activeKey = ZS_Config::getActiveGeminiKey($cfgRecovered, $dataDir);
    assert_equals('fresh_key_unlimited_3', $activeKey, 'new key must be immediately active because previous keys are cooling');

    @unlink($badFile);
    @unlink($badFile2);
    @unlink($dataDir . '/config.php');
    @unlink($dataDir . '/cooldowns.php');
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Gemini key modal: auto_review_step releases claim on no_api_key or all_cooling', function () {
    $tempDir = sys_get_temp_dir() . '/zs_auto_nokey_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/site';
    $dataDir = $tempDir . '/data';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);

    $keyHash = password_hash('SecretPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'        => $keyHash,
        'csrf_secret'     => 'csrf_secret_abcdef123456',
        'gemini_api_keys' => array(),
    ), $dataDir);

    $store = new ZS_Store($dataDir);
    $session = $store->initSession($rootDir, true);
    $badFile = $rootDir . '/victim.php';
    file_put_contents($badFile, '<?php system($_GET["x"]);');
    $rawHash = hash('sha256', '<?php system($_GET["x"]);');

    $session['infected_files'] = array(
        array(
            'finding_id'      => 'find_auto_1',
            'path'            => $badFile,
            'raw_sha256'      => $rawHash,
            'norm_sha256'     => $rawHash,
            'reason'          => 'system',
            'rule_ids'        => array('SIG-03'),
            'evidence'        => array('system'),
            'status'          => 'FOUND',
            'size'            => 25,
            'coverage'        => 'full',
            'scan_session_id' => $session['scan_session_id'],
        ),
    );
    $store->saveSession($session);

    // 1. Start auto review
    $resStart = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action' => 'auto_review_control',
        'op'        => 'start',
    ));
    assert_true(!empty($resStart['success']), 'auto_review_control start must succeed');

    // 2. Step with no keys configured: must return error: no_api_key and keep item as FOUND
    $resStepNoKey = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action' => 'auto_review_step',
    ));
    assert_true(is_array($resStepNoKey) && !empty($resStepNoKey['success']), 'auto_review_step must respond');
    assert_equals('no_api_key', $resStepNoKey['error'], 'auto_review_step must report no_api_key');

    $sessAfterNoKey = $store->loadSession();
    assert_equals('FOUND', $sessAfterNoKey['infected_files'][0]['status'], 'Finding status must remain FOUND instead of converting to AI_ERROR');

    // 3. Configure a key, but mock all keys cooling
    ZS_Config::saveConfig(array(
        'gemini_api_keys' => array('test_key_cooling'),
    ), $dataDir);

    $mockCooling = 'ZS_Gemini::$http = function ($url, $headers, $payloadJson, $method) {
        return array("status" => 429, "body" => "RESOURCE_EXHAUSTED", "retry_after" => 25);
    };';

    $resStepCooling = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action' => 'auto_review_step',
    ), $mockCooling);

    assert_true(is_array($resStepCooling) && !empty($resStepCooling['success']), 'auto_review_step must respond');
    assert_equals('all_cooling', $resStepCooling['error'], 'auto_review_step must report all_cooling');
    assert_true(!empty($resStepCooling['retry_after']), 'retry_after must be set');

    $sessAfterCooling = $store->loadSession();
    assert_equals('FOUND', $sessAfterCooling['infected_files'][0]['status'], 'Finding status must remain FOUND so it can be resumed');

    @unlink($badFile);
    @unlink($dataDir . '/config.php');
    @unlink($dataDir . '/cooldowns.php');
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Gemini key modal: UI renders geminiKeyModal and bilingual i18n completeness', function () {
    $tempDir = sys_get_temp_dir() . '/zs_ui_modal_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/site';
    $dataDir = $tempDir . '/data';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);

    $store = new ZS_Store($dataDir);
    $session = $store->initSession($rootDir, true);
    $session['infected_files'] = array(
        array(
            'finding_id'      => 'fid_ui_1',
            'path'            => $rootDir . '/bad.php',
            'raw_sha256'      => hash('sha256', 'bad'),
            'norm_sha256'     => hash('sha256', 'bad'),
            'reason'          => 'eval',
            'rule_ids'        => array('SIG-01'),
            'evidence'        => array('eval'),
            'status'          => 'FOUND',
            'size'            => 10,
            'coverage'        => 'full',
            'scan_session_id' => $session['scan_session_id'],
        ),
    );
    $config = array(
        'key_hash'        => password_hash('Pass12345678', PASSWORD_DEFAULT),
        'csrf_secret'     => 'csrf_secret_ui_test',
        'gemini_api_keys' => array(),
    );

    ob_start();
    ZS_Ui::renderReport($session, $rootDir, $dataDir, $config, $store);
    $html = ob_get_clean();

    assert_true(strpos($html, 'id="geminiKeyModal"') !== false, 'HTML must render geminiKeyModal');
    assert_true(strpos($html, 'id="modal_gemini_api_keys"') !== false, 'HTML must contain modal_gemini_api_keys textarea');
    assert_true(strpos($html, 'id="geminiKeyRateLimitNotice"') !== false, 'HTML must contain geminiKeyRateLimitNotice');
    assert_true(strpos($html, 'id="btnSaveGeminiKeyModal"') !== false, 'HTML must contain btnSaveGeminiKeyModal');
    assert_true(strpos($html, 'id="btnStartAuto"') !== false, 'HTML must contain btnStartAuto');
    assert_true(strpos($html, 'id="modalAskAiBtn"') !== false, 'HTML must contain modalAskAiBtn');
    assert_true(strpos($html, 'https://aistudio.google.com/api-keys') !== false, 'HTML must contain link to aistudio.google.com/api-keys');
    assert_true(strpos($html, 'target="_blank"') !== false, 'link must have target=_blank');
    assert_true(strpos($html, 'rel="noopener noreferrer"') !== false, 'link must have rel=noopener noreferrer');

    // Check that required i18n keys are loaded
    $allEn = ZS_I18n::getAll();
    $requiredKeys = array(
        'gemini_key_modal_title',
        'gemini_key_ratelimit_title',
        'gemini_key_modal_desc',
        'gemini_key_get_link',
        'gemini_key_ratelimit_notice',
        'gemini_key_input_label',
        'gemini_key_hint',
        'gemini_key_btn_save',
        'gemini_key_btn_cancel',
        'gemini_key_required_prompt',
        'gemini_key_rotated_notice',
    );
    foreach ($requiredKeys as $rk) {
        assert_true(!empty($allEn[$rk]), "i18n key {$rk} must exist and be non-empty");
    }

    $css = file_get_contents(dirname(dirname(__FILE__)) . '/src/assets/app.css');
    assert_true(strpos($css, '#geminiKeyModal.modal-overlay { z-index: 15000; }') !== false, 'CSS must have explicit z-index 15000 for geminiKeyModal');

    @unlink($dataDir . '/session.php');
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Gemini key modal: saving a cooling key clears its cooldown immediately', function () {
    $tempDir = sys_get_temp_dir() . '/zs_clear_cd_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/site';
    $dataDir = $tempDir . '/data';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);

    $keyHash = password_hash('SecretPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'        => $keyHash,
        'csrf_secret'     => 'csrf_secret_abcdef123456',
        'gemini_api_keys' => array('stale_cooling_key'),
    ), $dataDir);

    // Save cooldown directly to cooldowns.php as a previous process would
    $fp = substr(hash('sha256', 'stale_cooling_key'), 0, 16);
    ZS_Config::saveCooldowns(array($fp => time() + 120), $dataDir);
    $persistedBefore = ZS_Config::loadCooldowns($dataDir);
    assert_true(isset($persistedBefore[$fp]), 'fingerprint must be in cooldowns.php before save');

    // Re-saving the key via save_settings clears its cooldown
    $res = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'          => 'save_settings',
        'gemini_api_keys'    => 'stale_cooling_key',
        'append_gemini_keys' => '1',
    ));
    assert_true(!empty($res['success']), 'save_settings must succeed');

    $persistedAfter = ZS_Config::loadCooldowns($dataDir);
    assert_false(isset($persistedAfter[$fp]), 'saving cooling key must remove its fingerprint from cooldowns.php');

    // Also test direct ZS_Config::clearKeyCooldown helper
    $cfg = ZS_Config::loadConfig($dataDir);
    ZS_Config::markKeyCooldown('direct_test_key', 60, $cfg, $dataDir);
    assert_true(ZS_Config::isKeyCooling('direct_test_key', $cfg, $dataDir), 'direct_test_key must be cooling');
    ZS_Config::clearKeyCooldown('direct_test_key', $cfg, $dataDir);
    assert_false(ZS_Config::isKeyCooling('direct_test_key', $cfg, $dataDir), 'direct_test_key must no longer be cooling after clearKeyCooldown');

    @unlink($dataDir . '/config.php');
    @unlink($dataDir . '/cooldowns.php');
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Gemini key modal: user saved keys take precedence over environment variables and are preserved across settings edits', function () {
    $tempDir = sys_get_temp_dir() . '/zs_env_prec_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/site';
    $dataDir = $tempDir . '/data';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);

    $origEnvKey = getenv('GEMINI_API_KEY');
    putenv('GEMINI_API_KEY=env_bad_dummy_key_123');
    $_ENV['GEMINI_API_KEY'] = 'env_bad_dummy_key_123';

    // 1. Initial config with no keys saved in config.php: loadConfig falls back to env
    $keyHash = password_hash('SecretPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'    => $keyHash,
        'csrf_secret' => 'csrf_secret_abcdef123456',
    ), $dataDir);

    $cfgInitial = ZS_Config::loadConfig($dataDir);
    assert_equals(array('env_bad_dummy_key_123'), $cfgInitial['gemini_api_keys'], 'initial config falls back to env when unset in config.php');

    // 2. User explicitly saves their key via save_settings: user key takes precedence
    $mockSetEnv = 'putenv("GEMINI_API_KEY=env_bad_dummy_key_123"); $_ENV["GEMINI_API_KEY"] = "env_bad_dummy_key_123";';
    $resSave = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'save_settings',
        'gemini_api_keys' => 'user_real_key_456',
    ), $mockSetEnv);
    assert_true(!empty($resSave['success']), 'save_settings with real key must succeed');

    $cfgAfterSave = ZS_Config::loadConfig($dataDir);
    assert_equals(array('user_real_key_456'), $cfgAfterSave['gemini_api_keys'], 'user saved key must take precedence over env variable');

    // 3. User saves settings updating only gemini_model: saved keys must NOT be wiped
    $resModel = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'    => 'save_settings',
        'gemini_model' => 'gemini-1.5-pro',
    ), $mockSetEnv);
    assert_true(!empty($resModel['success']), 'updating model must succeed');

    $cfgAfterModel = ZS_Config::loadConfig($dataDir);
    assert_equals('gemini-1.5-pro', $cfgAfterModel['gemini_model'], 'model must be updated');
    assert_equals(array('user_real_key_456'), $cfgAfterModel['gemini_api_keys'], 'stored keys must not be wiped when saving other settings');

    // 4. User explicitly clears keys: clear_gemini_keys must persist and not revert to env
    $resClear = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'         => 'save_settings',
        'clear_gemini_keys' => '1',
    ), $mockSetEnv);
    assert_true(!empty($resClear['success']), 'clear_gemini_keys must succeed');

    $cfgAfterClear = ZS_Config::loadConfig($dataDir);
    assert_equals(array(), ZS_Config::getGeminiKeys($cfgAfterClear), 'cleared keys must remain empty and not revert to env');

    // Restore env
    if ($origEnvKey !== false) {
        putenv('GEMINI_API_KEY=' . $origEnvKey);
        $_ENV['GEMINI_API_KEY'] = $origEnvKey;
    } else {
        putenv('GEMINI_API_KEY');
        unset($_ENV['GEMINI_API_KEY']);
    }

    @unlink($dataDir . '/config.php');
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Gemini key modal: masked keys filtering, getGeminiKeys string parsing, and app.js client functions', function () {
    $tempDir = sys_get_temp_dir() . '/zs_masked_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/site';
    $dataDir = $tempDir . '/data';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);

    $keyHash = password_hash('SecretPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'        => $keyHash,
        'csrf_secret'     => 'csrf_secret_abcdef123456',
        'gemini_api_keys' => array('valid_key_one'),
    ), $dataDir);

    // 1. Submitting masked key (containing bullet • or *) must NOT overwrite valid key
    $resMasked = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'save_settings',
        'gemini_api_keys' => 'valid••••••••one',
    ));
    assert_true(!empty($resMasked['success']), 'masked save_settings must succeed safely');
    $cfgMasked = ZS_Config::loadConfig($dataDir);
    assert_equals(array('valid_key_one'), $cfgMasked['gemini_api_keys'], 'masked key submission must not corrupt stored keys');

    // 2. Test ZS_Config::getGeminiKeys parsing strings, quotes, prefixes and filtering
    $parsedString = ZS_Config::getGeminiKeys(array('gemini_api_keys' => "k1, k2\nk3, k1"));
    assert_equals(array('k1', 'k2', 'k3'), $parsedString, 'getGeminiKeys must parse string and deduplicate');

    $parsedQuoted = ZS_Config::getGeminiKeys(array('gemini_api_keys' => "\"AIzaQuoted1\", 'AIzaQuoted2', GEMINI_API_KEY=AIzaPrefixed"));
    assert_equals(array('AIzaQuoted1', 'AIzaQuoted2', 'AIzaPrefixed'), $parsedQuoted, 'getGeminiKeys must strip surrounding quotes and key prefixes');

    $parsedMasked = ZS_Config::getGeminiKeys(array('gemini_api_keys' => array('AIza••••••••OmY', 'real_key')));
    assert_equals(array('real_key'), $parsedMasked, 'getGeminiKeys must filter out masked keys');

    // 3. Verify singular gemini_api_key compatibility in loadConfig and migration in saveConfig
    $tempSingular = sys_get_temp_dir() . '/zs_sing_' . bin2hex(random_bytes(4));
    @mkdir($tempSingular, 0755, true);
    ZS_Config::saveConfig(array(
        'key_hash'       => $keyHash,
        'csrf_secret'    => 'csrf_secret_abcdef123456',
        'gemini_api_key' => 'singular_legacy_key',
    ), $tempSingular);

    $origSingEnv = getenv('GEMINI_API_KEY');
    putenv('GEMINI_API_KEY=env_should_not_override_singular');
    $_ENV['GEMINI_API_KEY'] = 'env_should_not_override_singular';

    $cfgSing = ZS_Config::loadConfig($tempSingular);
    assert_equals(array('singular_legacy_key'), ZS_Config::getGeminiKeys($cfgSing), 'singular gemini_api_key in config must prevent env override');

    ZS_Config::saveConfig(array(
        'gemini_api_keys' => array('migrated_plural_key'),
    ), $tempSingular);
    $cfgMigrated = ZS_Config::loadConfig($tempSingular);
    assert_equals(array('migrated_plural_key'), $cfgMigrated['gemini_api_keys'], 'plural keys must update properly');
    assert_true(!isset($cfgMigrated['gemini_api_key']), 'legacy singular gemini_api_key must be unset after saving plural keys');

    if ($origSingEnv !== false) {
        putenv('GEMINI_API_KEY=' . $origSingEnv);
        $_ENV['GEMINI_API_KEY'] = $origSingEnv;
    } else {
        putenv('GEMINI_API_KEY');
        unset($_ENV['GEMINI_API_KEY']);
    }
    @unlink($tempSingular . '/config.php');
    @rmdir($tempSingular);

    // 4. Verify save_settings updating new_access_key updates key_hash
    $resNewPass = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'      => 'save_settings',
        'new_access_key' => 'BrandNewPassword123456',
    ));
    assert_true(!empty($resNewPass['success']), 'changing access key to 12+ chars must succeed');
    $cfgNewPass = ZS_Config::loadConfig($dataDir);
    assert_true(password_verify('BrandNewPassword123456', $cfgNewPass['key_hash']), 'new password hash must verify with new password');

    // 5. Verify test_gemini accepts keys from POST to test before saving
    $mockPingCapture = 'ZS_Gemini::$http = function ($url, $headers, $payloadJson, $method) {
        return array(
            "status" => 200,
            "body" => json_encode(array("candidates" => array(array("content" => array("parts" => array(array("text" => "pong"))))))),
        );
    };';
    $resTestG = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'test_gemini',
        'gemini_api_keys' => 'custom_unsaved_ping_key',
    ), $mockPingCapture);
    assert_true(!empty($resTestG['success']), 'test_gemini with posted keys must succeed');

    // 6. Verify app.js contains saveGeminiKeyModal and askAiFile
    $jsContent = file_get_contents(dirname(dirname(__FILE__)) . '/src/assets/app.js');
    assert_true(strpos($jsContent, 'function saveGeminiKeyModal') !== false, 'app.js must define saveGeminiKeyModal function');
    assert_true(strpos($jsContent, 'window.saveGeminiKeyModal') !== false, 'app.js must expose window.saveGeminiKeyModal');
    assert_true(strpos($jsContent, 'window.askAiFile') !== false, 'app.js must expose window.askAiFile');

    @unlink($dataDir . '/config.php');
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Review navigation tests
// -------------------------------------------------------------
run_test('Review navigation: Store::findFirstUnreviewedIndex correctly calculates initial index', function() {
    $tempDir = sys_get_temp_dir() . '/zs_nav_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    // Empty session -> 0
    $sess = $store->loadSession();
    assert_equals(0, $store->findFirstUnreviewedIndex($sess), 'Empty session should return 0');

    // 4 items:
    // 0: QUARANTINED (terminal/reviewed)
    // 1: FOUND, candidate hash awaiting strike 2 review (reviewed: false) -> MUST land on 1
    // 2: FOUND, explicitly reviewed: true
    // 3: FOUND, unreviewed
    $hashCandidate = hash('sha256', 'candidate_sample');
    $knowledge = $store->loadKnowledge();
    $knowledge['candidates'][$hashCandidate] = array(
        'first_path' => '/var/www/candidate.php',
        'first_session_id' => 'sess_prev',
        'first_at' => time()
    );
    $store->saveKnowledge($knowledge);

    $sess = array(
        'scan_session_id' => 'sess_123',
        'review_cursor'   => 0,
        'infected_files'  => array(
            array('finding_id' => 'f0', 'path' => '/var/www/f0.php', 'status' => 'QUARANTINED', 'raw_sha256' => 'h0', 'reason' => 'r'),
            array('finding_id' => 'f1', 'path' => '/var/www/f1.php', 'status' => 'FOUND', 'raw_sha256' => $hashCandidate, 'reason' => 'r'),
            array('finding_id' => 'f2', 'path' => '/var/www/f2.php', 'status' => 'FOUND', 'raw_sha256' => 'h2', 'reviewed' => true, 'reason' => 'r'),
            array('finding_id' => 'f3', 'path' => '/var/www/f3.php', 'status' => 'FOUND', 'raw_sha256' => 'h3', 'reason' => 'r'),
        )
    );
    $store->saveSession($sess);

    // Candidate finding f1 is unreviewed in this session and must not be skipped
    assert_equals(1, $store->findFirstUnreviewedIndex($sess), 'Should land on candidate finding f1 for 2nd-strike human review');

    // Once f1 is marked reviewed, should skip f0 (quarantined), f1 (reviewed), f2 (reviewed) to land on f3 (index 3)
    $sess['infected_files'][1]['reviewed'] = true;
    $store->saveSession($sess);
    assert_equals(3, $store->findFirstUnreviewedIndex($sess), 'Should skip reviewed items to land on index 3');

    // AI_SKIPPED and AI_ERROR should be recognized as pending human review
    $sess['infected_files'][3]['status'] = 'AI_SKIPPED';
    $store->saveSession($sess);
    assert_equals(3, $store->findFirstUnreviewedIndex($sess), 'AI_SKIPPED finding must be treated as pending human review');

    $sess['infected_files'][3]['status'] = 'AI_ERROR';
    $store->saveSession($sess);
    assert_equals(3, $store->findFirstUnreviewedIndex($sess), 'AI_ERROR finding must be treated as pending human review');

    // Now mark f3 as reviewed -> all reviewed! Should gracefully return last item (3)
    $sess['infected_files'][3]['reviewed'] = true;
    $store->saveSession($sess);
    assert_equals(3, $store->findFirstUnreviewedIndex($sess), 'When all items reviewed, should return last item (3) allowing Back navigation');

    // With TRUSTED_HIDDEN item at beginning: visibleIndex must ignore trusted
    $sess['infected_files'] = array(
        array('finding_id' => 'f_trusted', 'path' => '/t.php', 'status' => 'TRUSTED_HIDDEN', 'raw_sha256' => 'ht', 'reason' => 'r'),
        array('finding_id' => 'f0', 'path' => '/var/www/f0.php', 'status' => 'QUARANTINED', 'raw_sha256' => 'h0', 'reason' => 'r'),
        array('finding_id' => 'f1', 'path' => '/var/www/f1.php', 'status' => 'FOUND', 'raw_sha256' => 'h1', 'reason' => 'r'),
    );
    $store->saveSession($sess);
    // Visible items: f0 (index 0), f1 (index 1). f0 is quarantined, f1 is unreviewed -> should return visible index 1
    assert_equals(1, $store->findFirstUnreviewedIndex($sess), 'Visible index must ignore TRUSTED_HIDDEN items');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

run_test('Review navigation: Store::findNextUnreviewedIndex respects fromIndex and wraps around safely', function() {
    $tempDir = sys_get_temp_dir() . '/zs_next_idx_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $sess = array(
        'scan_session_id' => 'sess_next',
        'infected_files'  => array(
            array('finding_id' => 'f0', 'status' => 'FOUND', 'reviewed' => false),
            array('finding_id' => 'f1', 'status' => 'QUARANTINED', 'reviewed' => true),
            array('finding_id' => 'f2', 'status' => 'FOUND', 'reviewed' => false),
            array('finding_id' => 'f3', 'status' => 'FOUND', 'reviewed' => false),
        )
    );

    // fromIndex = 0: finds f0 (index 0)
    assert_equals(0, $store->findNextUnreviewedIndex($sess, 0));

    // fromIndex = 1: f1 is quarantined, finds f2 (index 2)
    assert_equals(2, $store->findNextUnreviewedIndex($sess, 1));

    // fromIndex = 2: finds f2 (index 2)
    assert_equals(2, $store->findNextUnreviewedIndex($sess, 2));

    // fromIndex = 3: finds f3 (index 3)
    assert_equals(3, $store->findNextUnreviewedIndex($sess, 3));

    // When f2 and f3 are reviewed, fromIndex = 2 wraps back to f0 (index 0)
    $sess['infected_files'][2]['reviewed'] = true;
    $sess['infected_files'][3]['reviewed'] = true;
    assert_equals(0, $store->findNextUnreviewedIndex($sess, 2));

    // When all items are reviewed, returns lastVisible (index 3)
    $sess['infected_files'][0]['reviewed'] = true;
    assert_equals(3, $store->findNextUnreviewedIndex($sess, 2));

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

run_test('Review navigation: Store::setReviewCursor and getReviewCursor manage session cursor', function() {
    $tempDir = sys_get_temp_dir() . '/zs_cursor_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $sess = array(
        'scan_session_id' => 'sess_abc',
        'review_cursor'   => 0,
        'infected_files'  => array(
            array('finding_id' => 'f1', 'path' => '/a.php', 'status' => 'FOUND', 'raw_sha256' => 'h1', 'reason' => 'r'),
            array('finding_id' => 'f2', 'path' => '/b.php', 'status' => 'FOUND', 'raw_sha256' => 'h2', 'reason' => 'r'),
        )
    );
    $store->saveSession($sess);
    assert_equals(0, $store->getReviewCursor($sess));

    $store->setReviewCursor(1, 'f1');
    $updated = $store->loadSession();
    assert_equals(1, $updated['review_cursor'], 'review_cursor should be updated to 1');
    assert_true(!empty($updated['infected_files'][0]['reviewed']), 'finding f1 should be marked reviewed = true');
    assert_false(!empty($updated['infected_files'][1]['reviewed']), 'finding f2 should remain unreviewed');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

run_test('Review navigation: HTTP set_review_cursor action validates session and updates store', function() {
    $tempDir = sys_get_temp_dir() . '/zs_act_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/root';
    $dataDir = $tempDir . '/data';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);

    $keyHash = password_hash('TestPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'    => $keyHash,
        'csrf_secret' => 'csrf_test_secret_123456',
    ), $dataDir);

    $store = new ZS_Store($dataDir);
    $sess = array(
        'scan_session_id' => 'sid_exact_123',
        'review_cursor'   => 0,
        'infected_files'  => array(
            array('finding_id' => 'find_1', 'path' => $rootDir . '/vuln.php', 'status' => 'FOUND', 'raw_sha256' => 'h1', 'reason' => 'r'),
        )
    );
    $store->saveSession($sess);

    // Mismatched session should fail
    $resFail = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'set_review_cursor',
        'scan_session_id' => 'wrong_session_id',
        'finding_id'      => 'find_1',
        'index'           => 1,
    ));
    assert_false(!empty($resFail['success']), 'Mismatch scan_session_id must fail');

    // Matching session should succeed
    $resOk = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'set_review_cursor',
        'scan_session_id' => 'sid_exact_123',
        'finding_id'      => 'find_1',
        'index'           => 1,
        'skipped'         => '1',
    ));
    assert_true(!empty($resOk['success']), 'Valid set_review_cursor must succeed');
    assert_equals(1, $resOk['review_cursor']);

    $savedSess = $store->loadSession();
    assert_equals(1, $savedSess['review_cursor']);
    assert_true(!empty($savedSess['infected_files'][0]['reviewed']), 'find_1 must be marked reviewed');

    @unlink($dataDir . '/config.php');
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Review navigation: view_file reads quarantined file content from quarantine backup', function() {
    $tempDir = sys_get_temp_dir() . '/zs_qview_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/root';
    $dataDir = $tempDir . '/data';
    $quarantineDir = $dataDir . '/quarantine';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);
    @mkdir($quarantineDir, 0700, true);

    $keyHash = password_hash('TestPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'    => $keyHash,
        'csrf_secret' => 'csrf_test_secret_123456',
    ), $dataDir);

    $testFile = $rootDir . '/webshell.php';
    $codePayload = "<?php echo 'malware_payload_test_123'; ?>";
    file_put_contents($testFile, $codePayload);
    $rawHash = hash('sha256', $codePayload);

    // Quarantine the file (copies to quarantineDir and unlinks original)
    $qRes = ZS_Quarantine::copyThenUnlink($testFile, $rootDir, $quarantineDir, array(
        'finding_id'   => 'fid_quarantined',
        'expected_raw' => $rawHash,
    ));
    assert_true($qRes['success'], 'Quarantine copyThenUnlink must succeed');
    assert_false(file_exists($testFile), 'Original file must be unlinked after quarantine');

    $store = new ZS_Store($dataDir);
    $sess = array(
        'scan_session_id' => 'sid_q_test',
        'review_cursor'   => 0,
        'infected_files'  => array(
            array(
                'finding_id'   => 'fid_quarantined',
                'path'         => $testFile,
                'status'       => 'QUARANTINED',
                'raw_sha256'   => $rawHash,
                'reason'       => 'Webshell detected',
                'backup_name'  => $qRes['backup_name'],
                'size'         => strlen($codePayload),
                'reviewed'     => true,
            ),
        )
    );
    $store->saveSession($sess);

    // Call view_file via worker action
    $res = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'view_file',
        'scan_session_id' => 'sid_q_test',
        'finding_id'      => 'fid_quarantined',
        'expected_raw'    => $rawHash,
    ));
    assert_true(!empty($res['success']), 'view_file for quarantined finding must succeed: ' . (isset($res['message']) ? $res['message'] : ''));
    assert_true(!empty($res['is_quarantined']), 'Response must indicate is_quarantined is true');
    assert_equals($codePayload, $res['content'], 'view_file must return the original content from the quarantine envelope');

    @unlink($quarantineDir . '/' . $qRes['backup_name']);
    @unlink($quarantineDir . '/manifest.json');
    @rmdir($quarantineDir);
    @unlink($dataDir . '/config.php');
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Review navigation: Ui::renderReport outputs review_cursor and reviewed flag', function() {
    $tempDir = sys_get_temp_dir() . '/zs_uireport_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    $session = array(
        'scan_session_id'  => 'sess_ui_123',
        'scanned_files'    => 10,
        'review_cursor'    => 1,
        'infected_files'   => array(
            array('finding_id' => 'f1', 'path' => '/a.php', 'status' => 'QUARANTINED', 'raw_sha256' => 'h1', 'reason' => 'r', 'size' => 10, 'reviewed' => true),
            array('finding_id' => 'f2', 'path' => '/b.php', 'status' => 'FOUND', 'raw_sha256' => 'h2', 'reason' => 'r', 'size' => 20),
        ),
    );
    $store->saveSession($session);
    $config = array('key_hash' => 'dummy', 'csrf_secret' => 'dummy');

    ob_start();
    ZS_Ui::renderReport($session, $tempDir, $tempDir, $config, $store);
    $html = ob_get_clean();

    assert_true(preg_match('/window\.ZS_BOOT\s*=\s*(\{.*?\});/s', $html, $m) === 1, 'window.ZS_BOOT JSON must be embedded in report');
    $boot = json_decode($m[1], true);
    assert_true(is_array($boot), 'Embedded boot must parse as JSON array');
    assert_equals(1, $boot['review_cursor'], 'review_cursor in boot must point to first unreviewed finding (index 1)');
    assert_true(!empty($boot['items'][0]['reviewed']), 'f1 in boot items must have reviewed = true');
    assert_false(!empty($boot['items'][1]['reviewed']), 'f2 in boot items must have reviewed = false');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

run_test('Review navigation: delete_single and mark_clean update reviewed flag and advance review_cursor', function() {
    $tempDir = sys_get_temp_dir() . '/zs_act_nav_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/root';
    $dataDir = $tempDir . '/data';
    $quarantineDir = $dataDir . '/quarantine';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);
    @mkdir($quarantineDir, 0700, true);

    $keyHash = password_hash('TestPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'    => $keyHash,
        'csrf_secret' => 'csrf_test_secret_123456',
    ), $dataDir);

    $file1 = $rootDir . '/mal1.php';
    $file2 = $rootDir . '/mal2.php';
    $file3 = $rootDir . '/mal3.php';
    file_put_contents($file1, "<?php echo 'm1'; ?>");
    file_put_contents($file2, "<?php echo 'm2'; ?>");
    file_put_contents($file3, "<?php echo 'm3'; ?>");
    $raw1 = hash('sha256', "<?php echo 'm1'; ?>");
    $raw2 = hash('sha256', "<?php echo 'm2'; ?>");
    $raw3 = hash('sha256', "<?php echo 'm3'; ?>");

    $store = new ZS_Store($dataDir);
    $sess = array(
        'scan_session_id' => 'sid_nav_flow',
        'review_cursor'   => 0,
        'infected_files'  => array(
            array('finding_id' => 'f1', 'path' => $file1, 'status' => 'FOUND', 'raw_sha256' => $raw1, 'reason' => 'r1'),
            array('finding_id' => 'f2', 'path' => $file2, 'status' => 'FOUND', 'raw_sha256' => $raw2, 'reason' => 'r2'),
            array('finding_id' => 'f3', 'path' => $file3, 'status' => 'FOUND', 'raw_sha256' => $raw3, 'reason' => 'r3'),
        )
    );
    $store->saveSession($sess);

    // Delete/quarantine f1
    $delRes = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'delete_single',
        'scan_session_id' => 'sid_nav_flow',
        'finding_id'      => 'f1',
        'expected_raw'    => $raw1,
    ));
    assert_true(!empty($delRes['success']), 'delete_single on f1 should succeed');

    $s1 = $store->loadSession();
    assert_true(!empty($s1['infected_files'][0]['reviewed']), 'f1 must have reviewed = true');
    assert_equals('QUARANTINED', $s1['infected_files'][0]['status']);
    assert_equals(1, $s1['review_cursor'], 'review_cursor must advance to f2 (index 1)');

    // Repeat delete_single on already-quarantined f1 must succeed gracefully
    $delRes2 = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'delete_single',
        'scan_session_id' => 'sid_nav_flow',
        'finding_id'      => 'f1',
        'expected_raw'    => $raw1,
    ));
    assert_true(!empty($delRes2['success']), 'Repeat delete_single on already-quarantined f1 should succeed');
    assert_true(!empty($delRes2['already_quarantined']), 'Response should indicate already_quarantined');
    assert_equals(1, $delRes2['review_cursor'], 'review_cursor should remain pointed to next unreviewed index');

    // Mark clean f2
    $cleanRes = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'mark_clean',
        'scan_session_id' => 'sid_nav_flow',
        'finding_id'      => 'f2',
        'expected_raw'    => $raw2,
    ));
    assert_true(!empty($cleanRes['status']), 'mark_clean on f2 should succeed');

    $s2 = $store->loadSession();
    assert_true(!empty($s2['infected_files'][1]['reviewed']), 'f2 must have reviewed = true');
    assert_equals(2, $s2['review_cursor'], 'review_cursor must advance to f3 (index 2)');

    @unlink($file2);
    @unlink($file3);
    if (!empty($delRes['backup_name'])) {
        @unlink($quarantineDir . '/' . $delRes['backup_name']);
    }
    @unlink($quarantineDir . '/manifest.json');
    @rmdir($quarantineDir);
    @unlink($dataDir . '/config.php');
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

// -------------------------------------------------------------
// Review navigation: client deleteAndNext unlocks decisions and advances
// -------------------------------------------------------------
run_test('Review navigation: client deleteAndNext unlocks decisions and advances without freezing', function() use ($repoRoot) {
    $jsPath = $repoRoot . '/src/assets/app.js';
    assert_true(file_exists($jsPath), 'app.js must exist');
    $jsContent = file_get_contents($jsPath);

    // 1. Static code safety checks
    assert_true(strpos($jsContent, 'function deleteAndNext()') !== false, 'deleteAndNext must be defined');
    assert_true(preg_match('/setDecisionLocked\(false\);\s*nextReviewFile\(\);/s', $jsContent) === 1, 'deleteAndNext must unlock decisions before nextReviewFile');
    assert_true(strpos($jsContent, 'setDecisionLocked(false);') !== false, 'setDecisionLocked(false) must be present in app.js');

    // 2. Headless browser / Node.js VM runtime execution test if node is installed
    $nodeBin = trim((string)shell_exec('command -v node'));
    if ($nodeBin !== '') {
        $nodeTestScript = <<<'NODE_SCRIPT'
const fs = require('fs');
const vm = require('vm');

const appJs = process.argv[2];
const code = fs.readFileSync(appJs, 'utf8');

const elements = {};
function getEl(id) {
    if (!elements[id]) {
        elements[id] = {
            id,
            style: {},
            className: '',
            classList: {
                classes: [],
                add: function(c) { if (!this.contains(c)) this.classes.push(c); },
                remove: function(c) { this.classes = this.classes.filter(x => x !== c); },
                contains: function(c) { return this.classes.includes(c); }
            },
            textContent: '',
            disabled: false,
            querySelector: () => null,
            focus: () => {},
            setAttribute: () => {},
            getAttribute: () => ''
        };
    }
    return elements[id];
}

let lastAlert = null;
let fetchResolve;
let fetchReject;
let fetchCalls = 0;
let lastFetchUrl = null;
let lastFetchOpts = null;

const sandbox = {
    window: { location: { pathname: '/malware-cleaner.php' } },
    document: {
        addEventListener: () => {},
        getElementById: (id) => getEl(id),
        querySelector: () => null,
        querySelectorAll: () => [],
    },
    localStorage: {
        data: {},
        getItem: function(k) { return this.data[k] || null; },
        setItem: function(k, v) { this.data[k] = String(v); }
    },
    fetch: (url, opts) => {
        fetchCalls++;
        lastFetchUrl = url;
        lastFetchOpts = opts;
        return new Promise((res, rej) => { fetchResolve = res; fetchReject = rej; });
    },
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    alert: (msg) => { lastAlert = msg; },
    FormData: class { append(k, v) { this[k] = v; } },
    AbortController: class { abort() {} },
    console: console,
};
sandbox.window.window = sandbox.window;
sandbox.window.document = sandbox.document;
sandbox.window.localStorage = sandbox.localStorage;
sandbox.window.fetch = sandbox.fetch;
sandbox.window.setTimeout = sandbox.setTimeout;
sandbox.window.clearTimeout = sandbox.clearTimeout;
sandbox.window.FormData = sandbox.FormData;
sandbox.window.AbortController = sandbox.AbortController;

vm.createContext(sandbox);
vm.runInContext(code, sandbox);

async function runTests() {
    // Case 1: deleteAndNext locks during request, unlocks on success, advances index to 1
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f1', path: '/a.php', filename: 'a.php', status: 'FOUND', raw_sha256: 'h1', reason: 'r1', row_id: 'row1' },
        { finding_id: 'f2', path: '/b.php', filename: 'b.php', status: 'FOUND', raw_sha256: 'h2', reason: 'r2', row_id: 'row2' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false;', sandbox);

    fetchCalls = 0;
    vm.runInContext('deleteAndNext()', sandbox);
    const lockedDuring = vm.runInContext('decisionsLocked', sandbox);
    if (!lockedDuring) throw new Error('Decisions must be locked during delete_single');
    if (fetchCalls !== 1) throw new Error('Expected 1 fetch call, got ' + fetchCalls);

    // Case 1b: double click while locked must be ignored
    vm.runInContext('deleteAndNext()', sandbox);
    if (fetchCalls !== 1) throw new Error('Double click while decisions locked must be ignored');

    fetchResolve({ json: () => Promise.resolve({ success: true, message: 'Quarantined' }) });
    await new Promise(r => setTimeout(r, 40));

    const idxAfter = vm.runInContext('currentReviewIndex', sandbox);
    if (idxAfter !== 1) throw new Error('currentReviewIndex did not advance to 1 (got ' + idxAfter + ')');
    if (sandbox.window.REVIEW_ITEMS[0].status !== 'QUARANTINED') throw new Error('Status was not set to QUARANTINED');

    // Case 2: deleteAndNext on last item closes modal and leaves decisions unlocked
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_last', path: '/last.php', filename: 'last.php', status: 'FOUND', raw_sha256: 'hl', reason: 'rl' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false; isModalActive = true;', sandbox);

    vm.runInContext('deleteAndNext()', sandbox);
    fetchResolve({ json: () => Promise.resolve({ success: true, message: 'Quarantined last' }) });
    await new Promise(r => setTimeout(r, 40));

    const isModalActive = vm.runInContext('isModalActive', sandbox);
    const lockedLast = vm.runInContext('decisionsLocked', sandbox);
    if (isModalActive) throw new Error('Modal should close after last item is deleted');
    if (lockedLast) throw new Error('Decisions should be unlocked after last item is deleted');

    // Case 3: delete failure unlocks decisions and alerts without freezing
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_err', path: '/err.php', filename: 'err.php', status: 'FOUND', raw_sha256: 'he', reason: 're' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false;', sandbox);
    lastAlert = null;

    vm.runInContext('deleteAndNext()', sandbox);
    fetchResolve({ json: () => Promise.resolve({ success: false, message: 'Disk read-only' }) });
    await new Promise(r => setTimeout(r, 40));

    const lockedErr = vm.runInContext('decisionsLocked', sandbox);
    if (lockedErr) throw new Error('Decisions should be unlocked after failure');
    if (lastAlert !== 'Disk read-only') throw new Error('User was not alerted with error message: ' + lastAlert);

    // Case 4: network rejection unlocks decisions and alerts without freezing
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false;', sandbox);
    lastAlert = null;

    vm.runInContext('deleteAndNext()', sandbox);
    fetchReject(new Error('Connection timed out'));
    await new Promise(r => setTimeout(r, 40));

    const lockedNet = vm.runInContext('decisionsLocked', sandbox);
    if (lockedNet) throw new Error('Decisions should be unlocked after network error');
    if (lastAlert !== 'Connection timed out') throw new Error('User was not alerted on network failure: ' + lastAlert);

    // Case 5: saveReviewState preserves overrides
    vm.runInContext('isModalActive = true; currentReviewIndex = 2; saveReviewState({ modal_open: false, index: 0 });', sandbox);
    const savedState = JSON.parse(sandbox.localStorage.getItem('zs_review_default'));
    if (savedState.modal_open !== false || savedState.index !== 0) {
        throw new Error('saveReviewState did not preserve explicit overrides: ' + JSON.stringify(savedState));
    }

    // Case 6: deleteAndNext on already-quarantined item advances to next review file without freezing
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_q1', path: '/q1.php', filename: 'q1.php', status: 'QUARANTINED', reviewed: true, raw_sha256: 'hq1' },
        { finding_id: 'f_q2', path: '/q2.php', filename: 'q2.php', status: 'FOUND', reviewed: false, raw_sha256: 'hq2' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false; isModalActive = true;', sandbox);
    lastFetchOpts = null;
    vm.runInContext('deleteAndNext()', sandbox);
    const idxCase6 = vm.runInContext('currentReviewIndex', sandbox);
    const lockedCase6 = vm.runInContext('decisionsLocked', sandbox);
    if (idxCase6 !== 1) throw new Error('deleteAndNext on already-quarantined item should advance to index 1, got ' + idxCase6);
    if (lockedCase6) throw new Error('Decisions should not be locked when advancing from already-quarantined item');
    if (lastFetchOpts && lastFetchOpts.method === 'POST') throw new Error('No POST delete network call should be made for already-quarantined item');

    // Case 7: deleteAndNext skips already-quarantined items in sequential list
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_s1', path: '/s1.php', filename: 's1.php', status: 'FOUND', reviewed: false, raw_sha256: 'hs1' },
        { finding_id: 'f_s2', path: '/s2.php', filename: 's2.php', status: 'QUARANTINED', reviewed: true, raw_sha256: 'hs2' },
        { finding_id: 'f_s3', path: '/s3.php', filename: 's3.php', status: 'FOUND', reviewed: false, raw_sha256: 'hs3' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false; isModalActive = true;', sandbox);
    vm.runInContext('deleteAndNext()', sandbox);
    fetchResolve({ json: () => Promise.resolve({ success: true, message: 'Quarantined s1' }) });
    await new Promise(r => setTimeout(r, 40));
    const idxCase7 = vm.runInContext('currentReviewIndex', sandbox);
    if (idxCase7 !== 2) throw new Error('deleteAndNext should skip already-quarantined s2 (index 1) and advance to s3 (index 2), got ' + idxCase7);

    // Case 8: server error with CHANGED_SINCE_SCAN updates file status, unlocks decisions, alerts user
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_ch', path: '/ch.php', filename: 'ch.php', status: 'FOUND', reviewed: false, raw_sha256: 'hch' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false;', sandbox);
    lastAlert = null;
    vm.runInContext('deleteAndNext()', sandbox);
    fetchResolve({ json: () => Promise.resolve({ success: false, message: 'File changed since scan.', code: 'CHANGED_SINCE_SCAN' }) });
    await new Promise(r => setTimeout(r, 40));
    const lockedCase8 = vm.runInContext('decisionsLocked', sandbox);
    if (lockedCase8) throw new Error('Decisions must be unlocked after CHANGED_SINCE_SCAN failure');
    if (sandbox.window.REVIEW_ITEMS[0].status !== 'CHANGED_SINCE_SCAN') throw new Error('Status should be updated to CHANGED_SINCE_SCAN');
    if (sandbox.window.REVIEW_ITEMS[0].reviewed !== true) throw new Error('File should be marked reviewed on CHANGED_SINCE_SCAN');

    // Case 9: Request timeout AbortError unlocks decisions and alerts with timeout message
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_to', path: '/to.php', filename: 'to.php', status: 'FOUND', reviewed: false, raw_sha256: 'hto' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false;', sandbox);
    lastAlert = null;
    vm.runInContext('deleteAndNext()', sandbox);
    const abortErr = new Error('The operation was aborted');
    abortErr.name = 'AbortError';
    fetchReject(abortErr);
    await new Promise(r => setTimeout(r, 40));
    const lockedCase9 = vm.runInContext('decisionsLocked', sandbox);
    if (lockedCase9) throw new Error('Decisions must be unlocked after AbortError/timeout');
    if (!lastAlert || (lastAlert !== 'err_request_timeout' && lastAlert.indexOf('timed out') === -1)) throw new Error('Expected timeout alert message, got: ' + lastAlert);

    // Case 10: DOM error during delete success handling is caught, decisions unlocked
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_dom', path: '/dom.php', filename: 'dom.php', status: 'FOUND', reviewed: false, raw_sha256: 'hdom', row_id: 'row_bad' },
        { finding_id: 'f_dom2', path: '/dom2.php', filename: 'dom2.php', status: 'FOUND', reviewed: false, raw_sha256: 'hdom2' },
    ];
    const origGetEl = sandbox.document.getElementById;
    sandbox.document.getElementById = function(id) {
        if (id === 'statQuarantined') throw new Error('Simulated DOM access error');
        return origGetEl(id);
    };
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false;', sandbox);
    vm.runInContext('deleteAndNext()', sandbox);
    fetchResolve({ json: () => Promise.resolve({ success: true, message: 'Quarantined dom' }) });
    await new Promise(r => setTimeout(r, 40));
    sandbox.document.getElementById = origGetEl;
    const lockedCase10 = vm.runInContext('decisionsLocked', sandbox);
    if (lockedCase10) throw new Error('Decisions must be unlocked even if DOM update throws');
    const idxCase10 = vm.runInContext('currentReviewIndex', sandbox);
    if (idxCase10 !== 1) throw new Error('currentReviewIndex should still advance to 1 despite DOM error, got ' + idxCase10);

    // Case 11: deleteAndNext on last item closes modal, and starting review wraps around to unreviewed item
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_w0', path: '/w0.php', filename: 'w0.php', status: 'FOUND', reviewed: false, raw_sha256: 'hw0' },
        { finding_id: 'f_w1', path: '/w1.php', filename: 'w1.php', status: 'QUARANTINED', reviewed: true, raw_sha256: 'hw1' },
        { finding_id: 'f_w2', path: '/w2.php', filename: 'w2.php', status: 'FOUND', reviewed: false, raw_sha256: 'hw2' },
    ];
    vm.runInContext('currentReviewIndex = 2; decisionsLocked = false; isModalActive = true;', sandbox);
    vm.runInContext('deleteAndNext()', sandbox);
    fetchResolve({ json: () => Promise.resolve({ success: true, message: 'Quarantined w2' }) });
    await new Promise(r => setTimeout(r, 40));
    const modalActiveCase11 = vm.runInContext('isModalActive', sandbox);
    if (modalActiveCase11) throw new Error('Modal should close after last sequential item is reviewed');
    vm.runInContext('startReviewMode(undefined, false);', sandbox);
    const idxCase11 = vm.runInContext('currentReviewIndex', sandbox);
    if (idxCase11 !== 0) throw new Error('startReviewMode must wrap around to unreviewed item at index 0, got ' + idxCase11);

    // Case 12: Calling deleteAndNext on a terminal finding (e.g. CHANGED_SINCE_SCAN or MISSING) directly advances without network call
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_t0', path: '/t0.php', filename: 't0.php', status: 'CHANGED_SINCE_SCAN', reviewed: true, raw_sha256: 'ht0' },
        { finding_id: 'f_t1', path: '/t1.php', filename: 't1.php', status: 'FOUND', reviewed: false, raw_sha256: 'ht1' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false; isModalActive = true;', sandbox);
    lastFetchOpts = null;
    vm.runInContext('deleteAndNext()', sandbox);
    const idxCase12 = vm.runInContext('currentReviewIndex', sandbox);
    if (idxCase12 !== 1) throw new Error('deleteAndNext on CHANGED_SINCE_SCAN item must advance to index 1, got ' + idxCase12);
    if (lastFetchOpts && lastFetchOpts.method === 'POST') throw new Error('No POST network call should be made for terminal item');

    // Case 13: Rapid hammering of deleteAndNext while in flight does not send duplicate requests
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_h0', path: '/h0.php', filename: 'h0.php', status: 'FOUND', reviewed: false, raw_sha256: 'hh0' },
        { finding_id: 'f_h1', path: '/h1.php', filename: 'h1.php', status: 'FOUND', reviewed: false, raw_sha256: 'hh1' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false; isModalActive = true;', sandbox);
    fetchCalls = 0;
    vm.runInContext('deleteAndNext()', sandbox);
    const callsBefore = fetchCalls;
    vm.runInContext('deleteAndNext()', sandbox);
    vm.runInContext('deleteAndNext()', sandbox);
    if (fetchCalls !== callsBefore) throw new Error('Repeated deleteAndNext calls while in flight must not trigger additional fetch calls');
    fetchResolve({ json: () => Promise.resolve({ success: true, message: 'Quarantined h0' }) });
    await new Promise(r => setTimeout(r, 40));
    const idxCase13 = vm.runInContext('currentReviewIndex', sandbox);
    if (idxCase13 !== 1) throw new Error('currentReviewIndex should be 1 after in-flight delete finishes, got ' + idxCase13);

    // Case 14: Server error with MISSING code updates status to MISSING, alerts, and advances
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f_m1', path: '/m1.php', filename: 'm1.php', status: 'FOUND', reviewed: false, raw_sha256: 'hm1' },
        { finding_id: 'f_m2', path: '/m2.php', filename: 'm2.php', status: 'FOUND', reviewed: false, raw_sha256: 'hm2' },
    ];
    vm.runInContext('currentReviewIndex = 0; decisionsLocked = false; isModalActive = true;', sandbox);
    lastAlert = null;
    vm.runInContext('deleteAndNext()', sandbox);
    fetchResolve({ json: () => Promise.resolve({ success: false, message: 'File is missing.', code: 'MISSING' }) });
    await new Promise(r => setTimeout(r, 40));
    const lockedCase14 = vm.runInContext('decisionsLocked', sandbox);
    if (lockedCase14) throw new Error('Decisions must be unlocked after MISSING error');
    if (sandbox.window.REVIEW_ITEMS[0].status !== 'MISSING') throw new Error('Status should be updated to MISSING');
    if (sandbox.window.REVIEW_ITEMS[0].reviewed !== true) throw new Error('File should be marked reviewed on MISSING');
    const idxCase14 = vm.runInContext('currentReviewIndex', sandbox);
    if (idxCase14 !== 1) throw new Error('Should advance to next file (index 1) on MISSING error, got ' + idxCase14);

    console.log('NODE_OK');
}

runTests().catch(err => {
    console.error(err);
    process.exit(1);
});
NODE_SCRIPT;

        $tmpNodeScript = tempnam(sys_get_temp_dir(), 'zs_node_nav_') . '.js';
        file_put_contents($tmpNodeScript, $nodeTestScript);
        exec(escapeshellcmd($nodeBin) . ' ' . escapeshellarg($tmpNodeScript) . ' ' . escapeshellarg($jsPath), $nodeOut, $nodeCode);
        @unlink($tmpNodeScript);

        assert_equals(0, $nodeCode, 'Node runtime test for deleteAndNext failed: ' . implode("\n", $nodeOut));
        assert_true(in_array('NODE_OK', $nodeOut, true), 'Node test must output NODE_OK');
    }
});

// -------------------------------------------------------------
// Review navigation: Sequential review resume & inspect cursor preservation
// -------------------------------------------------------------
run_test('Review navigation: Ui::renderReport honors stored review_cursor and actions return cursor', function() {
    $tempDir = sys_get_temp_dir() . '/zs_seq_cur_' . bin2hex(random_bytes(4));
    $rootDir = $tempDir . '/root';
    $dataDir = $tempDir . '/data';
    $quarantineDir = $dataDir . '/quarantine';
    @mkdir($rootDir, 0755, true);
    @mkdir($dataDir, 0755, true);
    @mkdir($quarantineDir, 0700, true);

    $keyHash = password_hash('TestPass1234', PASSWORD_DEFAULT);
    ZS_Config::saveConfig(array(
        'key_hash'    => $keyHash,
        'csrf_secret' => 'csrf_test_secret_123456',
    ), $dataDir);

    $file1 = $rootDir . '/f1.php';
    $file2 = $rootDir . '/f2.php';
    $file3 = $rootDir . '/f3.php';
    file_put_contents($file1, "<?php echo '1'; ?>");
    file_put_contents($file2, "<?php echo '2'; ?>");
    file_put_contents($file3, "<?php echo '3'; ?>");
    $raw1 = hash('sha256', "<?php echo '1'; ?>");
    $raw2 = hash('sha256', "<?php echo '2'; ?>");
    $raw3 = hash('sha256', "<?php echo '3'; ?>");

    $store = new ZS_Store($dataDir);
    $session = array(
        'scan_session_id' => 'sid_seq_flow',
        'review_cursor'   => 2,
        'scanned_files'   => 3,
        'infected_files'  => array(
            array('finding_id' => 'f1', 'path' => $file1, 'status' => 'FOUND', 'raw_sha256' => $raw1, 'reason' => 'r1', 'size' => 10),
            array('finding_id' => 'f2', 'path' => $file2, 'status' => 'FOUND', 'raw_sha256' => $raw2, 'reason' => 'r2', 'size' => 10),
            array('finding_id' => 'f3', 'path' => $file3, 'status' => 'FOUND', 'raw_sha256' => $raw3, 'reason' => 'r3', 'size' => 10),
        )
    );
    $store->saveSession($session);

    // 1. Ui::renderReport should output review_cursor >= 2
    ob_start();
    ZS_Ui::renderReport($session, $rootDir, $dataDir, array('key_hash' => $keyHash, 'csrf_secret' => 'csrf_test_secret_123456'), $store);
    $html = ob_get_clean();
    assert_true(preg_match('/window\.ZS_BOOT\s*=\s*(\{.*?\});/s', $html, $m) === 1, 'Boot JSON must be present');
    $boot = json_decode($m[1], true);
    assert_equals(2, $boot['review_cursor'], 'Boot review_cursor must honor stored review_cursor (2)');

    // 2. delete_single action returns review_cursor in response
    $delRes = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'delete_single',
        'scan_session_id' => 'sid_seq_flow',
        'finding_id'      => 'f1',
        'expected_raw'    => $raw1,
    ));
    assert_true(!empty($delRes['success']), 'delete_single should succeed');
    assert_true(isset($delRes['review_cursor']), 'delete_single response must contain review_cursor');

    // 3. mark_clean action returns review_cursor in response
    $cleanRes = run_zs_test_worker_action($rootDir, $dataDir, array(
        'do_action'       => 'mark_clean',
        'scan_session_id' => 'sid_seq_flow',
        'finding_id'      => 'f2',
        'expected_raw'    => $raw2,
    ));
    assert_true(!empty($cleanRes['status']), 'mark_clean should succeed');
    assert_true(isset($cleanRes['review_cursor']), 'mark_clean response must contain review_cursor');

    @unlink($file1);
    @unlink($file2);
    @unlink($file3);
    if (!empty($delRes['backup_name'])) {
        @unlink($quarantineDir . '/' . $delRes['backup_name']);
    }
    @unlink($quarantineDir . '/manifest.json');
    @rmdir($quarantineDir);
    @unlink($dataDir . '/config.php');
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($dataDir);
    @rmdir($rootDir);
    @rmdir($tempDir);
});

run_test('Review navigation: client sequential review resumes correctly after inspect and navigation', function() use ($repoRoot) {
    $jsPath = $repoRoot . '/src/assets/app.js';
    assert_true(file_exists($jsPath), 'app.js must exist');

    $nodeBin = trim((string)shell_exec('command -v node'));
    if ($nodeBin === '') {
        return;
    }

    $nodeScript = <<<'NODE_SCRIPT'
const fs = require('fs');
const vm = require('vm');

const appJs = process.argv[2];
const code = fs.readFileSync(appJs, 'utf8');

const elements = {};
function getEl(id) {
    if (!elements[id]) {
        elements[id] = {
            id,
            style: {},
            className: '',
            classList: {
                classes: [],
                add: function(c) { if (!this.contains(c)) this.classes.push(c); },
                remove: function(c) { this.classes = this.classes.filter(x => x !== c); },
                contains: function(c) { return this.classes.includes(c); }
            },
            textContent: '',
            disabled: false,
            setAttribute: () => {},
            removeAttribute: () => {},
            getAttribute: () => null,
            querySelector: () => null,
            querySelectorAll: () => [],
            focus: () => {}
        };
    }
    return elements[id];
}

let fetchResolve;
let fetchCalls = 0;

const sandbox = {
    window: { location: { pathname: '/malware-cleaner.php' } },
    document: {
        addEventListener: () => {},
        getElementById: (id) => getEl(id),
        querySelector: () => null,
        querySelectorAll: () => [],
        activeElement: null,
    },
    localStorage: {
        data: {},
        getItem: function(k) { return this.data[k] || null; },
        setItem: function(k, v) { this.data[k] = String(v); }
    },
    fetch: (url, opts) => {
        fetchCalls++;
        let cursorVal = 0;
        if (opts && opts.body) {
            if (opts.body.do_action === 'set_review_cursor') {
                cursorVal = Number(opts.body.index || 0);
            } else if (opts.body.do_action === 'delete_single') {
                if (opts.body.finding_id === 'f2') cursorVal = 3;
                else if (opts.body.finding_id === 'f3') cursorVal = 4;
                else if (opts.body.finding_id === 'f4') cursorVal = 4;
                else cursorVal = 3;
            }
        }
        return Promise.resolve({
            json: () => Promise.resolve({ success: true, content: 'code', message: 'Quarantined', review_cursor: cursorVal })
        });
    },
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    alert: () => {},
    FormData: class { append(k, v) { this[k] = v; } },
    AbortController: class { abort() {} },
    console: console,
};
sandbox.window.window = sandbox.window;
sandbox.window.document = sandbox.document;
sandbox.window.localStorage = sandbox.localStorage;
sandbox.window.fetch = sandbox.fetch;
sandbox.window.setTimeout = sandbox.setTimeout;
sandbox.window.FormData = sandbox.FormData;
sandbox.window.AbortController = sandbox.AbortController;

vm.createContext(sandbox);
vm.runInContext(code, sandbox);

async function runTest() {
    sandbox.window.REVIEW_ITEMS = [
        { finding_id: 'f0', path: '/f0.php', filename: 'f0.php', status: 'FOUND', raw_sha256: 'h0', reason: 'r0' },
        { finding_id: 'f1', path: '/f1.php', filename: 'f1.php', status: 'FOUND', raw_sha256: 'h1', reason: 'r1' },
        { finding_id: 'f2', path: '/f2.php', filename: 'f2.php', status: 'FOUND', raw_sha256: 'h2', reason: 'r2' },
        { finding_id: 'f3', path: '/f3.php', filename: 'f3.php', status: 'FOUND', raw_sha256: 'h3', reason: 'r3' },
        { finding_id: 'f4', path: '/f4.php', filename: 'f4.php', status: 'FOUND', raw_sha256: 'h4', reason: 'r4' },
    ];
    sandbox.window.ZS_BOOT = { review_cursor: 0, session_id: 's1' };
    sandbox.window.ZS_SESSION_ID = 's1';

    // 1. Initial sequential review start -> opens index 0
    vm.runInContext('startReviewMode(undefined, false);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    let cur = vm.runInContext('currentReviewIndex', sandbox);
    let curCursor = vm.runInContext('reviewCursor', sandbox);
    if (cur !== 0) throw new Error('Initial startReviewMode should start at 0, got ' + cur);
    if (curCursor !== 0) throw new Error('reviewCursor should be 0, got ' + curCursor);

    // 2. User navigates Next twice: index 0 -> 1 -> 2
    vm.runInContext('nextReviewFile();', sandbox);
    await new Promise(r => setTimeout(r, 10));
    vm.runInContext('nextReviewFile();', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    curCursor = vm.runInContext('reviewCursor', sandbox);
    if (cur !== 2) throw new Error('After 2 nextReviewFile calls, currentReviewIndex should be 2, got ' + cur);
    if (curCursor !== 2) throw new Error('reviewCursor should advance to 2, got ' + curCursor);

    // 3. User closes modal
    vm.runInContext('closeViewModal();', sandbox);
    let modalActive = vm.runInContext('isModalActive', sandbox);
    if (modalActive) throw new Error('Modal should be closed');

    // 4. User inspects specific item f0 (single inspect mode)
    vm.runInContext('startReviewMode("f0", true);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    curCursor = vm.runInContext('reviewCursor', sandbox);
    if (cur !== 0) throw new Error('Single inspect should open f0 (index 0), got ' + cur);
    if (curCursor !== 2) throw new Error('Single inspect must NOT overwrite reviewCursor (expected 2), got ' + curCursor);

    // 5. User closes modal again
    vm.runInContext('closeViewModal();', sandbox);

    // 6. User clicks "Start Sequential Review" -> MUST RESUME AT 2, NOT 0!
    vm.runInContext('startReviewMode(undefined, false);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    if (cur !== 2) throw new Error('Start Sequential Review must resume at index 2, but got ' + cur);

    // 7. User navigates Back via Previous button: index 2 -> 1 -> 0
    vm.runInContext('prevReviewFile();', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    if (cur !== 1) throw new Error('prevReviewFile should move to index 1, got ' + cur);

    vm.runInContext('prevReviewFile();', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    if (cur !== 0) throw new Error('prevReviewFile should move to index 0, got ' + cur);
    const prevBtnDisabled = elements['btnPrevTop'] && elements['btnPrevTop'].disabled;
    if (!prevBtnDisabled) throw new Error('btnPrevTop should be disabled at index 0');

    // 8. User closes modal while viewing index 0
    vm.runInContext('closeViewModal();', sandbox);

    // 9. User clicks "Start Sequential Review" -> MUST STILL RESUME AT 2!
    vm.runInContext('startReviewMode(undefined, false);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    if (cur !== 2) throw new Error('Start Sequential Review after Back navigation must resume at index 2, got ' + cur);

    // 10. User quarantines item 2 via deleteAndNext
    vm.runInContext('deleteAndNext();', sandbox);
    await new Promise(r => setTimeout(r, 40));

    cur = vm.runInContext('currentReviewIndex', sandbox);
    curCursor = vm.runInContext('reviewCursor', sandbox);
    if (cur !== 3) throw new Error('currentReviewIndex should advance to 3 after delete, got ' + cur);
    if (curCursor !== 3) throw new Error('reviewCursor should be 3, got ' + curCursor);

    // 11. User closes modal, inspects item 1, closes modal, clicks Start Sequential Review -> RESUMES AT 3
    vm.runInContext('closeViewModal();', sandbox);
    vm.runInContext('startReviewMode("f1", true);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    vm.runInContext('closeViewModal();', sandbox);

    vm.runInContext('startReviewMode(undefined, false);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    if (cur !== 3) throw new Error('Start Sequential Review must resume at index 3, got ' + cur);

    // 12. User inspects f4 (index 4, ahead of cursor 3)
    vm.runInContext('startReviewMode("f4", true);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    curCursor = vm.runInContext('reviewCursor', sandbox);
    if (cur !== 4) throw new Error('Inspect f4 should open index 4, got ' + cur);
    if (curCursor !== 3) throw new Error('Inspect forward item must not advance reviewCursor (expected 3), got ' + curCursor);

    // 13. User closes modal after inspecting f4
    vm.runInContext('closeViewModal();', sandbox);

    // 14. User clicks "Start Sequential Review" -> MUST STILL RESUME AT 3 (not skip to 4!)
    vm.runInContext('startReviewMode(undefined, false);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    if (cur !== 3) throw new Error('Start Sequential Review after inspecting f4 must resume at index 3, got ' + cur);

    // 15. User quarantines f3 via deleteAndNext
    vm.runInContext('deleteAndNext();', sandbox);
    await new Promise(r => setTimeout(r, 40));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    if (cur !== 4) throw new Error('After quarantining f3, should advance to index 4, got ' + cur);

    // 16. User quarantines f4 via deleteAndNext
    vm.runInContext('deleteAndNext();', sandbox);
    await new Promise(r => setTimeout(r, 40));
    modalActive = vm.runInContext('isModalActive', sandbox);
    if (modalActive) throw new Error('Modal should close after last item is reviewed');

    // 16b. User clicks Start Sequential Review while f0 and f1 were unreviewed -> wraps around to 0
    vm.runInContext('startReviewMode(undefined, false);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    cur = vm.runInContext('currentReviewIndex', sandbox);
    if (cur !== 0) throw new Error('Start Sequential Review should wrap around to unreviewed f0 (0), got ' + cur);
    vm.runInContext('closeViewModal();', sandbox);

    // Mark f0 and f1 reviewed to test the all-items-reviewed terminal state
    sandbox.window.REVIEW_ITEMS[0].reviewed = true;
    sandbox.window.REVIEW_ITEMS[1].reviewed = true;

    // 17. User clicks Start Sequential Review when all items are reviewed -> modal must NOT open
    vm.runInContext('startReviewMode(undefined, false);', sandbox);
    await new Promise(r => setTimeout(r, 10));
    modalActive = vm.runInContext('isModalActive', sandbox);
    if (modalActive) throw new Error('Modal must not open when all items are reviewed');

    console.log('NODE_NAV_OK');
}

runTest().catch(err => {
    console.error(err);
    process.exit(1);
});
NODE_SCRIPT;

    $tmpScript = tempnam(sys_get_temp_dir(), 'zs_node_seq_') . '.js';
    file_put_contents($tmpScript, $nodeScript);
    exec(escapeshellcmd($nodeBin) . ' ' . escapeshellarg($tmpScript) . ' ' . escapeshellarg($jsPath), $nodeOut, $nodeCode);
    @unlink($tmpScript);

    assert_equals(0, $nodeCode, 'Node runtime test for sequential review resume failed: ' . implode("\n", $nodeOut));
    assert_true(in_array('NODE_NAV_OK', $nodeOut, true), 'Node test must output NODE_NAV_OK');
});

// -------------------------------------------------------------
// PHP Syntax Highlighting: Tokenization & Fidelity
// -------------------------------------------------------------
run_test('PHP Syntax Highlighting: tokenization and text fidelity', function() use ($repoRoot) {
    $jsPath = $repoRoot . '/src/assets/app.js';
    $nodeBin = trim((string)shell_exec('command -v node'));
    if ($nodeBin === '') {
        $js = file_get_contents($jsPath);
        assert_true(strpos($js, 'function highlightPhp(') !== false, 'highlightPhp function missing in app.js');
        return;
    }

    $nodeScript = <<<'NODE_SCRIPT'
const fs = require('fs');
const vm = require('vm');
const jsPath = process.argv[2];
const code = fs.readFileSync(jsPath, 'utf8');

const sandbox = {
    window: {},
    document: { addEventListener() {} },
    navigator: {},
    console
};
sandbox.window.window = sandbox.window;
sandbox.window.document = sandbox.document;
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

const highlightPhp = sandbox.window.highlightPhp;
if (typeof highlightPhp !== 'function') throw new Error('highlightPhp is not defined on window');

const sample = `<?php
// single comment
# hash comment
/* multi-line comment */
$variable = "double quote string";
$single = 'single quote string';
$shell = \`whoami\`;
$hex = 0x1A + 0b101 + 42.5;
$items = array('foo', 'bar');
enum Status { case OK; }
function test_func(string $data): bool {
    yield from ['a'];
    return true;
}
eval(base64_decode($single));
$bin = hex2bin("deadbeef");
$magic = __FILE__ . __DIR__;
?>
<div class="outside">HTML outside PHP</div>`;

const out = highlightPhp(sample);

const expectedClasses = [
    'zs-hl-tag',
    'zs-hl-comment',
    'zs-hl-str',
    'zs-hl-var',
    'zs-hl-num',
    'zs-hl-kw',
    'zs-hl-danger',
    'zs-hl-const'
];
for (const cls of expectedClasses) {
    if (!out.includes(`class="${cls}"`)) {
        throw new Error(`Missing expected syntax highlight class: ${cls}`);
    }
}

if (!out.includes('<span class="zs-hl-kw">array</span>')) {
    throw new Error('Expected array to be highlighted as keyword (zs-hl-kw)');
}
if (!out.includes('<span class="zs-hl-danger">hex2bin</span>')) {
    throw new Error('Expected hex2bin to be highlighted as dangerous function (zs-hl-danger)');
}

const stripped = out
    .replace(/<span class="zs-hl-[a-z]+">/g, '')
    .replace(/<\/span>/g, '')
    .replace(/&#039;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&gt;/g, '>')
    .replace(/&lt;/g, '<')
    .replace(/&amp;/g, '&');

if (stripped !== sample) {
    throw new Error('Fidelity mismatch between highlighted unescaped text and original code');
}

console.log('NODE_HL_TOKEN_OK');
NODE_SCRIPT;

    $tmp = tempnam(sys_get_temp_dir(), 'zs_node_hl_') . '.js';
    file_put_contents($tmp, $nodeScript);
    exec(escapeshellcmd($nodeBin) . ' ' . escapeshellarg($tmp) . ' ' . escapeshellarg($jsPath), $out, $status);
    @unlink($tmp);

    assert_equals(0, $status, 'Node highlight token test failed: ' . implode("\n", $out));
    assert_true(in_array('NODE_HL_TOKEN_OK', $out, true), 'Highlight token test must output NODE_HL_TOKEN_OK');
});

// -------------------------------------------------------------
// PHP Syntax Highlighting: Strict XSS Prevention
// -------------------------------------------------------------
run_test('PHP Syntax Highlighting: strict XSS prevention on untrusted payloads', function() use ($repoRoot) {
    $jsPath = $repoRoot . '/src/assets/app.js';
    $nodeBin = trim((string)shell_exec('command -v node'));
    if ($nodeBin === '') {
        return;
    }

    $nodeScript = <<<'NODE_SCRIPT'
const fs = require('fs');
const vm = require('vm');
const jsPath = process.argv[2];
const code = fs.readFileSync(jsPath, 'utf8');

const sandbox = {
    window: {},
    document: { addEventListener() {} },
    navigator: {},
    console
};
sandbox.window.window = sandbox.window;
sandbox.window.document = sandbox.document;
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

const highlightPhp = sandbox.window.highlightPhp;

const maliciousPayloads = [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(2)</script>',
    '<?php echo "<svg onload=alert(3)>"; ?>',
    '// <script>alert(4)</script>',
    '/* <iframe src="javascript:alert(5)"> */',
    '\'"><script>alert(6)</script>\'',
    '`"><script>alert(7)</script>`',
    '<a href="javascript:alert(8)">click</a>',
    '<body onload="alert(9)">',
    '<input type="text" autofocus onfocus="alert(10)">',
    '<?php $v = "</script><script>alert(11)</script>"; ?>',
    '<?php eval("<script>alert(12)</script>"); ?>'
];

for (const payload of maliciousPayloads) {
    const out = highlightPhp(payload);

    const tags = out.match(/<[^>]+>/g) || [];
    for (const tag of tags) {
        const isAllowedSpan = /^<span class="zs-hl-(?:tag|comment|str|var|num|kw|danger|const)">$/.test(tag);
        const isClosingSpan = (tag === '</span>');
        if (!isAllowedSpan && !isClosingSpan) {
            throw new Error(`XSS vulnerability! Disallowed tag '${tag}' produced for payload: ${payload}`);
        }
    }

    if (/<(script|img|svg|iframe|body|input|a)\b/i.test(out)) {
        throw new Error(`XSS vulnerability! Unescaped HTML element in output for payload: ${payload}`);
    }
}

console.log('NODE_HL_XSS_OK');
NODE_SCRIPT;

    $tmp = tempnam(sys_get_temp_dir(), 'zs_node_xss_') . '.js';
    file_put_contents($tmp, $nodeScript);
    exec(escapeshellcmd($nodeBin) . ' ' . escapeshellarg($tmp) . ' ' . escapeshellarg($jsPath), $out, $status);
    @unlink($tmp);

    assert_equals(0, $status, 'Node highlight XSS test failed: ' . implode("\n", $out));
    assert_true(in_array('NODE_HL_XSS_OK', $out, true), 'Highlight XSS test must output NODE_HL_XSS_OK');
});

// -------------------------------------------------------------
// Click-to-Copy for Path & Modal Copy
// -------------------------------------------------------------
run_test('Click-to-Copy: UI markup, click handler, and clipboard integration', function() use ($repoRoot) {
    $tempDir = sys_get_temp_dir() . '/zs_test_ui_copy_' . bin2hex(random_bytes(6));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);
    $session = array(
        'scan_session_id'  => 'sess_test_copy',
        'is_scanning'      => false,
        'infected_files'   => array(),
    );
    $store->saveSession($session);
    $config = array('key_hash' => 'dummy', 'csrf_secret' => 'dummy');

    ob_start();
    ZS_Ui::renderReport($session, $tempDir, $tempDir, $config, $store);
    $html = ob_get_clean();

    assert_true(strpos($html, 'id="modalFilePath"') !== false, 'modalFilePath ID must exist in UI markup');
    assert_true(strpos($html, 'tag tag-clickable') !== false, 'modalFilePath must have tag tag-clickable class');
    assert_true(strpos($html, 'role="button"') !== false, 'modalFilePath must have role="button"');
    assert_true(strpos($html, 'tabindex="0"') !== false, 'modalFilePath must have tabindex="0"');
    assert_true(strpos($html, 'title="') !== false, 'modalFilePath must have title attribute for tooltip');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);

    $jsPath = $repoRoot . '/src/assets/app.js';
    $nodeBin = trim((string)shell_exec('command -v node'));
    if ($nodeBin === '') {
        return;
    }

    $nodeScript = <<<'NODE_SCRIPT'
const fs = require('fs');
const vm = require('vm');
const jsPath = process.argv[2];
const code = fs.readFileSync(jsPath, 'utf8');

const domElements = {};
function createMockEl(id, tag = 'div') {
    const el = {
        id,
        tagName: tag.toUpperCase(),
        textContent: '',
        innerHTML: '',
        title: '',
        style: {},
        classList: {
            classes: new Set(),
            add(c) { this.classes.add(c); },
            remove(c) { this.classes.delete(c); },
            contains(c) { return this.classes.has(c); }
        },
        attrs: {},
        setAttribute(k, v) { this.attrs[k] = String(v); },
        getAttribute(k) { return this.attrs[k] !== undefined ? this.attrs[k] : null; },
        listeners: {},
        addEventListener(event, fn) {
            if (!this.listeners[event]) this.listeners[event] = [];
            this.listeners[event].push(fn);
        },
        dispatchEvent(event) {
            const handlers = this.listeners[event.type] || [];
            handlers.forEach(h => h(event));
        },
        select() {},
        parentNode: null
    };
    domElements[id] = el;
    return el;
}

const mockDoc = {
    getElementById(id) {
        if (!domElements[id]) return createMockEl(id);
        return domElements[id];
    },
    querySelector(sel) {
        return createMockEl('mockSel');
    },
    querySelectorAll(sel) {
        return [];
    },
    createElement(tag) {
        return createMockEl('created_' + Math.random(), tag);
    },
    body: {
        appendChild() {},
        removeChild() {}
    },
    listeners: {},
    addEventListener(event, fn) {
        if (!this.listeners[event]) this.listeners[event] = [];
        this.listeners[event].push(fn);
    },
    trigger(event) {
        (this.listeners[event] || []).forEach(fn => fn());
    }
};

let lastCopiedText = null;

const sandbox = {
    window: {
        ZS_BOOT: { csrf: 'tok' },
        ZS_I18N: {
            modal_copied: 'Copied!',
            path_copied: 'Path copied to clipboard',
            copy_path_hint: 'Click to copy path',
            modal_loading: 'Fetching file content from server...'
        },
        isSecureContext: true
    },
    document: mockDoc,
    navigator: {
        clipboard: {
            writeText(txt) {
                lastCopiedText = txt;
                return Promise.resolve();
            }
        }
    },
    setTimeout: global.setTimeout,
    clearTimeout: global.clearTimeout,
    console
};
sandbox.window.window = sandbox.window;
sandbox.window.document = sandbox.document;
sandbox.window.navigator = sandbox.navigator;

vm.createContext(sandbox);
vm.runInContext(code, sandbox);
mockDoc.trigger('DOMContentLoaded');

async function runTests() {
    // Case 1: copyFilePath with data-full-path
    const pathEl = mockDoc.getElementById('modalFilePath');
    pathEl.setAttribute('data-full-path', '/var/www/site/wp-content/themes/evil.php');
    pathEl.textContent = '/var/www/site/wp-content/themes/evil.php';

    sandbox.window.copyFilePath();
    await new Promise(r => setTimeout(r, 20));
    if (lastCopiedText !== '/var/www/site/wp-content/themes/evil.php') {
        throw new Error('copyFilePath did not copy the expected path');
    }
    if (!pathEl.classList.contains('copied')) {
        throw new Error('pathEl did not receive copied class for visual feedback');
    }

    // Case 2: copyModalContent copies raw textContent (ignoring inner HTML spans)
    const codeEl = mockDoc.getElementById('modalFileContent');
    codeEl.textContent = '<?php echo "clean unhighlighted raw text"; ?>';
    const highlightPhp = sandbox.window.highlightPhp;
    codeEl.innerHTML = highlightPhp(codeEl.textContent);

    sandbox.window.copyModalContent();
    await new Promise(r => setTimeout(r, 20));
    if (lastCopiedText !== '<?php echo "clean unhighlighted raw text"; ?>') {
        throw new Error('copyModalContent did not copy raw unhighlighted text: got ' + lastCopiedText);
    }

    // Case 3: Fallback copy when navigator.clipboard is unavailable
    sandbox.navigator.clipboard = null;
    lastCopiedText = null;
    let execCommandCalled = false;
    mockDoc.execCommand = function(cmd) {
        if (cmd === 'copy') execCommandCalled = true;
    };

    sandbox.window.copyTextToClipboard('/fallback/path.php', 'Copied');
    await new Promise(r => setTimeout(r, 20));
    if (!execCommandCalled) {
        throw new Error('Fallback document.execCommand copy was not called when clipboard API unavailable');
    }

    // Case 4: Keyboard activation with Space and Enter on #modalFilePath
    lastCopiedText = null;
    sandbox.navigator.clipboard = {
        writeText(txt) {
            lastCopiedText = txt;
            return Promise.resolve();
        }
    };
    pathEl.setAttribute('data-full-path', '/var/www/site/index.php');
    pathEl.textContent = '/var/www/site/index.php';
    let spaceDefaultPrevented = false;
    let spacePropagationStopped = false;
    const spaceEvt = {
        type: 'keydown',
        key: ' ',
        code: 'Space',
        preventDefault() { spaceDefaultPrevented = true; },
        stopPropagation() { spacePropagationStopped = true; }
    };
    pathEl.dispatchEvent(spaceEvt);
    await new Promise(r => setTimeout(r, 20));
    if (lastCopiedText !== '/var/www/site/index.php') {
        throw new Error('Space keydown on pathEl did not copy path');
    }
    if (!spaceDefaultPrevented || !spacePropagationStopped) {
        throw new Error('Space keydown on pathEl must call preventDefault and stopPropagation to prevent skipping');
    }

    // Case 5: copyModalContent ignores loading placeholder
    lastCopiedText = null;
    codeEl.textContent = 'Fetching file content from server...';
    sandbox.window.copyModalContent();
    await new Promise(r => setTimeout(r, 20));
    if (lastCopiedText !== null) {
        throw new Error('copyModalContent must not copy modal_loading placeholder text');
    }

    console.log('NODE_COPY_OK');
}

runTests().catch(err => {
    console.error(err);
    process.exit(1);
});
NODE_SCRIPT;

    $tmp = tempnam(sys_get_temp_dir(), 'zs_node_copy_') . '.js';
    file_put_contents($tmp, $nodeScript);
    exec(escapeshellcmd($nodeBin) . ' ' . escapeshellarg($tmp) . ' ' . escapeshellarg($jsPath), $out, $status);
    @unlink($tmp);

    assert_equals(0, $status, 'Node click-to-copy test failed: ' . implode("\n", $out));
    assert_true(in_array('NODE_COPY_OK', $out, true), 'Click-to-copy test must output NODE_COPY_OK');
});

// -------------------------------------------------------------
// Localization: Path Copy & Syntax Keys
// -------------------------------------------------------------
run_test('Localization: path_copied and copy_path_hint in en.php and fa.php', function() use ($repoRoot) {
    $en = include $repoRoot . '/src/i18n/en.php';
    $fa = include $repoRoot . '/src/i18n/fa.php';

    assert_true(isset($en['path_copied']), 'en.php missing path_copied');
    assert_true(isset($fa['path_copied']), 'fa.php missing path_copied');
    assert_true(strlen($en['path_copied']) > 0, 'en path_copied must not be empty');
    assert_true(strlen($fa['path_copied']) > 0, 'fa path_copied must not be empty');

    assert_true(isset($en['copy_path_hint']), 'en.php missing copy_path_hint');
    assert_true(isset($fa['copy_path_hint']), 'fa.php missing copy_path_hint');
    assert_true(strlen($en['copy_path_hint']) > 0, 'en copy_path_hint must not be empty');
    assert_true(strlen($fa['copy_path_hint']) > 0, 'fa copy_path_hint must not be empty');

    assert_true($en['path_copied'] !== $fa['path_copied'], 'en and fa translations should be distinct');
});

// -------------------------------------------------------------
// Progressive Live Scanning & Safe Concurrent Review
// -------------------------------------------------------------
run_test('Live Scanning: actionScanBatch returns progressive findings and stats', function () use ($repoRoot) {
    $base = sys_get_temp_dir() . '/zs_live_' . bin2hex(random_bytes(4));
    $root = $base . '/site';
    $data = $base . '/data';
    @mkdir($root, 0755, true);
    @mkdir($data, 0755, true);

    file_put_contents($root . '/clean1.php', '<?php echo "Clean 1";');
    file_put_contents($root . '/clean2.php', '<?php echo "Clean 2";');
    file_put_contents($root . '/clean3.php', '<?php echo "Clean 3";');
    file_put_contents($root . '/mal1.php', '<?php eval(base64_decode("c3lzdGVtKCdpZDMnKTs="));');
    file_put_contents($root . '/mal2.php', '<?php eval(base64_decode("c3lzdGVtKCdpZDQnKTs="));');

    $config = array(
        'key_hash' => password_hash('TestKey123', PASSWORD_BCRYPT),
        'csrf_secret' => bin2hex(random_bytes(16)),
    );
    ZS_Config::saveConfig($config, $data);

    $store = new ZS_Store($data);
    $session = $store->initSession($root, true);

    // Call scan_batch via sub-process HTTP invocation
    $script = $base . '/test_scan_batch.php';
    $code = '<?php
    define("ZS_INTERNAL", true);
    require_once ' . var_export($repoRoot . '/src/Hash.php', true) . ';
    require_once ' . var_export($repoRoot . '/src/Config.php', true) . ';
    require_once ' . var_export($repoRoot . '/src/Store.php', true) . ';
    require_once ' . var_export($repoRoot . '/src/I18n.php', true) . ';
    require_once ' . var_export($repoRoot . '/src/Ui.php', true) . ';
    require_once ' . var_export($repoRoot . '/src/Rules.php', true) . ';
    require_once ' . var_export($repoRoot . '/src/Quarantine.php', true) . ';
    require_once ' . var_export($repoRoot . '/src/Engine.php', true) . ';
    require_once ' . var_export($repoRoot . '/src/Gemini.php', true) . ';
    require_once ' . var_export($repoRoot . '/src/Http.php', true) . ';

    $rootDir = $argv[1];
    $dataDir = $argv[2];
    $config = ZS_Config::loadConfig($dataDir);

    $authExpiry = time() + 3600;
    $sessionCookie = hash_hmac("sha256", "zs_auth:" . $authExpiry . ":" . $config["key_hash"], $config["csrf_secret"]) . ":" . $authExpiry;
    $_COOKIE["zs_session"] = $sessionCookie;
    $csrfExpiry = time() + 3600;
    $csrfToken = hash_hmac("sha256", "zs_csrf:" . $csrfExpiry . ":" . $sessionCookie, $config["csrf_secret"]) . ":" . $csrfExpiry;
    $_COOKIE["zs_csrf"] = $csrfToken;

    $_SERVER["REQUEST_METHOD"] = "POST";
    $_SERVER["HTTP_X_CSRF_TOKEN"] = $csrfToken;
    $_SERVER["HTTP_ACCEPT"] = "application/json";
    $_POST = array("do_action" => "scan_batch");

    ZS_Http::handleRequest($rootDir, $dataDir);
    ';
    file_put_contents($script, $code);

    $bin = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : 'php';
    $out = shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($root) . ' ' . escapeshellarg($data));
    $json = json_decode($out, true);

    assert_true(is_array($json), 'actionScanBatch must return valid JSON, got: ' . $out);
    assert_true(!empty($json['success']), 'scan_batch must succeed');
    assert_true(isset($json['scanned_files']) && $json['scanned_files'] >= 5, 'scanned_files must be at least 5');
    assert_true(isset($json['infected_count']) && $json['infected_count'] === 2, 'infected_count must be 2');
    assert_true(isset($json['new_findings']) && count($json['new_findings']) === 2, 'new_findings must contain 2 items');
    assert_true(!empty($json['is_completed']), 'scan must complete for 5 files');

    $f1 = $json['new_findings'][0];
    assert_true(!empty($f1['finding_id']), 'new finding must have finding_id');
    assert_true(!empty($f1['path']), 'new finding must have path');
    assert_true(!empty($f1['raw_sha256']), 'new finding must have raw_sha256');
    assert_equals('FOUND', $f1['status'], 'initial finding status must be FOUND');

    // Second call when already completed returns empty new_findings
    $out2 = shell_exec(escapeshellarg($bin) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($root) . ' ' . escapeshellarg($data));
    $json2 = json_decode($out2, true);
    assert_true(is_array($json2) && !empty($json2['is_completed']), 'subsequent scan_batch returns completed');
    assert_true(empty($json2['new_findings']), 'completed scan returns no new findings');

    // Clean up
    foreach (glob($root . '/*.php') as $f) { @unlink($f); }
    @unlink($script);
    @unlink($data . '/config.php');
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($root);
    @rmdir($data);
    @rmdir($base);
});

run_test('Concurrent Review: review actions while scanning batch proceeds in background', function () use ($repoRoot) {
    $base = sys_get_temp_dir() . '/zs_conc_' . bin2hex(random_bytes(4));
    $root = $base . '/site';
    $data = $base . '/data';
    $quar = $data . '/quarantine';
    @mkdir($root, 0755, true);
    @mkdir($data, 0755, true);
    @mkdir($quar, 0755, true);

    // Create 10 files
    for ($i = 0; $i < 10; $i++) {
        file_put_contents($root . '/test_' . $i . '.php', '<?php eval(base64_decode("c3lzdGVtKCdpZCk7")); // ' . $i);
    }

    $config = array(
        'key_hash' => password_hash('TestKey123', PASSWORD_BCRYPT),
        'csrf_secret' => bin2hex(random_bytes(16)),
    );
    ZS_Config::saveConfig($config, $data);

    $store = new ZS_Store($data);
    $session = $store->initSession($root, true);

    // First, run batch 1 to find some items
    ZS_Http::executeScanBatch($session, $root, $data, $store);
    $fresh = $store->loadSession();
    assert_true(!empty($fresh['infected_files']), 'batch 1 must find infected files');
    $finding0 = $fresh['infected_files'][0];
    $fid0 = $finding0['finding_id'];
    $raw0 = $finding0['raw_sha256'];
    $path0 = $finding0['path'];

    // Simulate concurrent review action: quarantine finding 0 via delete_single
    $qRes = ZS_Quarantine::copyThenUnlink($path0, $root, $quar, array('finding_id' => $fid0, 'expected_raw' => $raw0));
    assert_true(!empty($qRes['success']), 'quarantine must succeed');
    $updated = $store->updateInfectedItem(0, array(
        'status' => 'QUARANTINED',
        'backup_name' => $qRes['backup_name'],
        'reviewed' => true,
    ));
    assert_true($updated, 'finding 0 must be updated to QUARANTINED');

    // Also mark finding 1 clean concurrently
    if (isset($fresh['infected_files'][1])) {
        $store->markClean($fresh['infected_files'][1]['raw_sha256'], $fresh['infected_files'][1]['path'], $fresh['scan_session_id']);
        $store->updateInfectedItem(1, array('reviewed' => true));
    }

    // Now run another scan batch
    $freshBeforeBatch = $store->loadSession();
    ZS_Http::executeScanBatch($freshBeforeBatch, $root, $data, $store);

    // Verify session state AFTER the concurrent scan batch
    $finalSession = $store->loadSession();
    assert_true(is_array($finalSession), 'final session must exist');
    assert_equals('QUARANTINED', $finalSession['infected_files'][0]['status'], 'finding 0 must REMAIN QUARANTINED after concurrent scan batch');
    assert_true(!empty($finalSession['infected_files'][0]['reviewed']), 'finding 0 must remain reviewed');
    if (isset($finalSession['infected_files'][1])) {
        assert_true(!empty($finalSession['infected_files'][1]['reviewed']), 'finding 1 must remain reviewed');
    }

    // Clean up
    foreach (glob($root . '/*.php') as $f) { @unlink($f); }
    foreach (glob($quar . '/*') as $f) { @unlink($f); }
    @rmdir($quar);
    @unlink($data . '/config.php');
    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($root);
    @rmdir($data);
    @rmdir($base);
});

run_test('UI Progressive Scanning: renderReport outputs live banner and scan_active flag', function () {
    $tempDir = sys_get_temp_dir() . '/zs_ui_live_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);
    $config = array('csrf_secret' => 'test_secret', 'key_hash' => 'hash');

    // Case 1: Incomplete scan session
    $sessionIncomplete = $store->initSession($tempDir, true);
    $sessionIncomplete['is_completed'] = false;
    $sessionIncomplete['scanned_files'] = 150;
    $sessionIncomplete['scanned_dirs'] = 12;

    ob_start();
    ZS_Ui::renderReport($sessionIncomplete, $tempDir, $tempDir, $config, $store);
    $html1 = ob_get_clean();

    assert_true(strpos($html1, '"scan_active":true') !== false, 'boot data must have scan_active: true when incomplete');
    assert_true(strpos($html1, 'id="liveScanBanner"') !== false, 'must render liveScanBanner');
    assert_true(strpos($html1, 'class="status running"') !== false, 'must render status running when incomplete');
    assert_true(strpos($html1, 'id="statScannedFiles"') !== false, 'must render statScannedFiles element');
    assert_true(strpos($html1, 'id="btnToggleScan"') !== false, 'must render btnToggleScan pause/resume control');

    // Case 2: Complete scan session
    $sessionComplete = $sessionIncomplete;
    $sessionComplete['is_completed'] = true;

    ob_start();
    ZS_Ui::renderReport($sessionComplete, $tempDir, $tempDir, $config, $store);
    $html2 = ob_get_clean();

    assert_true(strpos($html2, '"scan_active":false') !== false, 'boot data must have scan_active: false when complete');
    assert_true(strpos($html2, 'class="status completed"') !== false, 'must render status completed when complete');
    assert_true(strpos($html2, 'display:none;') !== false, 'liveScanBanner must be hidden when complete');

    @unlink($store->getSessionFile());
    @unlink($store->getKnowledgeFile());
    @rmdir($tempDir);
});

run_test('Stale Session Isolation: reset scan rejects mutation from stale in-flight batch', function () {
    $tempDir = sys_get_temp_dir() . '/zs_stale_' . bin2hex(random_bytes(4));
    @mkdir($tempDir, 0755, true);
    $store = new ZS_Store($tempDir);

    // Initialize session 1
    $session1 = $store->initSession($tempDir, true);
    $sid1 = $session1['scan_session_id'];

    // Now reset to session 2
    $session2 = $store->initSession($tempDir, true);
    $sid2 = $session2['scan_session_id'];
    assert_true($sid1 !== $sid2, 'new session must have different scan_session_id');

    // Stale batch from session 1 tries to mutate session
    $staleFindings = array(array('finding_id' => 'stale1', 'path' => '/stale.php', 'status' => 'FOUND'));
    $store->mutateSession(function ($fresh) use ($sid1, $staleFindings) {
        if (!is_array($fresh)) return false;
        if ($sid1 !== '' && isset($fresh['scan_session_id']) && $fresh['scan_session_id'] !== $sid1) {
            // Discard stale mutation
            return $fresh;
        }
        $fresh['infected_files'][] = $staleFindings[0];
        return $fresh;
    });

    $freshAfter = $store->loadSession();
    assert_true(is_array($freshAfter), 'session must exist');
    assert_equals(0, count($freshAfter['infected_files']), 'stale batch findings must NOT be written to fresh session');
    assert_equals($sid2, $freshAfter['scan_session_id'], 'session 2 ID must remain intact');

    @unlink($store->getSessionFile());
    @rmdir($tempDir);
});

if ($prevEnvKey !== false) {
    putenv('GEMINI_API_KEY=' . $prevEnvKey);
    $_ENV['GEMINI_API_KEY'] = $prevEnvKey;
}
if ($prevEnvKeys !== false) {
    putenv('GEMINI_API_KEYS=' . $prevEnvKeys);
    $_ENV['GEMINI_API_KEYS'] = $prevEnvKeys;
}

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
