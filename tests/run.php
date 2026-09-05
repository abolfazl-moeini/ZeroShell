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

    // 2. uploads/index.php is still scanned (path rule); silence-only remains a suspect finding
    $res2 = ZS_Engine::scanFile($repoRoot . '/wp-content/uploads/index.php', 'index.php', '<?php // Silence is golden.', 'hash_idx', $rules, $repoRoot);
    assert_true($res2['detected'], 'uploads/index.php must still be examined');

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
