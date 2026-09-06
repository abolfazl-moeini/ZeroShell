<?php
class ZS_Store {
    private $dataDir;
    public $lastError = '';

    public function __construct($dataDir = null) {
        if ($dataDir === null) {
            $dataDir = ZS_Config::getDataDir();
        }
        $this->dataDir = $dataDir;
        ZS_Config::initDataDir($this->dataDir);
    }

    public function getDataDir() {
        return $this->dataDir;
    }

    public function getSessionFile() {
        return $this->dataDir . '/session.php';
    }

    public function getKnowledgeFile() {
        return $this->dataDir . '/knowledge.php';
    }

    private function lockFile($kind) {
        return $this->dataDir . '/.lock_' . $kind;
    }

    public function withNamedLock($kind, $callback) {
        if (!ZS_Config::secureMkdir($this->dataDir)) {
            $this->lastError = 'Data directory is not writable.';
            return false;
        }
        $lockPath = $this->lockFile($kind);
        $fp = @fopen($lockPath, 'c+');
        if (!$fp) {
            $this->lastError = 'Unable to open lock file.';
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            $this->lastError = 'Unable to acquire lock.';
            return false;
        }
        $ok = false;
        try {
            $ok = call_user_func($callback);
        } catch (Exception $e) {
            $this->lastError = $e->getMessage();
            $ok = false;
        }
        flock($fp, LOCK_UN);
        fclose($fp);
        return $ok;
    }

    private function defaultKnowledge() {
        return array(
            'schema_version'     => 2,
            'trusted'            => array(),
            'candidates'         => array(),
            'ai_cache'           => array(),
            'legacy_unverified'  => array(),
            'login_attempts'     => array(),
            'key_cooldowns'      => array(),
            'auto_review'        => self::defaultAutoReview(),
        );
    }

    public static function defaultAutoReview() {
        return array(
            'status'      => 'idle',
            'job_id'      => '',
            'stats'       => array(
                'pending'     => 0,
                'processing'  => 0,
                'skipped'     => 0,
                'cache_hits'  => 0,
                'failures'    => 0,
                'quarantined' => 0,
                'restored'    => 0,
            ),
            'updated_at'  => 0,
        );
    }

    private function defaultSession($rootDir) {
        return array(
            'scan_session_id'  => bin2hex(random_bytes(16)),
            'generation'       => 1,
            'dir_queue'        => array($rootDir),
            'dir_cursor'       => array('dir' => '', 'offset' => 0, 'names' => array()),
            'visited_dirs'     => array(),
            'scanned_files'    => 0,
            'scanned_dirs'     => 0,
            'trusted_bypassed' => 0,
            'skipped_unreadable' => 0,
            'skipped_symlink'  => 0,
            'skipped_large'    => 0,
            'coverage_partial' => 0,
            'infected_files'   => array(),
            'start_time'       => time(),
            'is_completed'     => false,
            'current_dir'      => $rootDir,
            'auto_review'      => self::defaultAutoReview(),
        );
    }

    private function migrateKnowledge($data) {
        if (!is_array($data)) {
            return $this->defaultKnowledge();
        }
        if (isset($data['schema_version']) && intval($data['schema_version']) >= 2) {
            $base = $this->defaultKnowledge();
            return array_merge($base, $data);
        }
        $legacy = array();
        foreach (array('trusted', 'candidates', 'ai_cache') as $section) {
            if (!empty($data[$section]) && is_array($data[$section])) {
                $legacy[$section] = $data[$section];
            }
        }
        $out = $this->defaultKnowledge();
        $out['legacy_unverified'] = $legacy;
        return $out;
    }

    private function readJsonFile($path) {
        if (!file_exists($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            $this->lastError = 'Unable to read ' . basename($path);
            return false;
        }
        if (trim($raw) === '') {
            $this->lastError = basename($path) . ' is empty.';
            return false;
        }
        $data = ZS_Config::unwrapJson($raw);
        if (!is_array($data)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                return $decoded;
            }
            $this->lastError = basename($path) . ' is corrupt.';
            return false;
        }
        return $data;
    }

    public function writeJsonFile($path, $data) {
        $wrapped = ZS_Config::wrapJson($data);
        if ($wrapped === false) {
            $this->lastError = 'Failed to encode JSON for ' . basename($path);
            return false;
        }
        return ZS_Config::atomicWrite($path, $wrapped, 0600);
    }

    public function loadKnowledge() {
        $file = $this->getKnowledgeFile();
        if (!file_exists($file)) {
            return $this->defaultKnowledge();
        }
        $data = $this->readJsonFile($file);
        if ($data === false) {
            return false;
        }
        if ($data === null) {
            return $this->defaultKnowledge();
        }
        return $this->migrateKnowledge($data);
    }

    public function saveKnowledge($data) {
        $file = $this->getKnowledgeFile();
        $store = $this;
        $ok = $this->withNamedLock('knowledge', function () use ($store, $file, $data) {
            return $store->writeJsonFile($file, $data);
        });
        return $ok ? true : false;
    }

    public function mutateKnowledge($mutator) {
        $file = $this->getKnowledgeFile();
        $store = $this;
        $result = null;
        $ok = $this->withNamedLock('knowledge', function () use ($store, $file, $mutator, &$result) {
            $data = $store->loadKnowledgeUnlocked();
            if ($data === false) {
                return false;
            }
            $result = call_user_func($mutator, $data);
            if (is_array($result) && isset($result['_knowledge'])) {
                $data = $result['_knowledge'];
                unset($result['_knowledge']);
            } elseif (is_array($result) && isset($result['schema_version'])) {
                $data = $result;
                $result = array('ok' => true);
            }
            if (!$store->writeJsonFile($file, $data)) {
                $store->lastError = 'Failed to write knowledge file.';
                return false;
            }
            return true;
        });
        if ($ok === false) {
            return false;
        }
        return $result;
    }

    public function loadKnowledgeUnlocked() {
        $file = $this->getKnowledgeFile();
        if (!file_exists($file)) {
            return $this->defaultKnowledge();
        }
        $data = $this->readJsonFile($file);
        if ($data === false) {
            return false;
        }
        if ($data === null) {
            return $this->defaultKnowledge();
        }
        return $this->migrateKnowledge($data);
    }

    public function loadSession() {
        $file = $this->getSessionFile();
        if (!file_exists($file)) {
            return null;
        }
        $data = $this->readJsonFile($file);
        if ($data === false) {
            return false;
        }
        return is_array($data) ? $data : null;
    }

    public function saveSession($session) {
        $file = $this->getSessionFile();
        $store = $this;
        return $this->withNamedLock('session', function () use ($store, $file, $session) {
            return $store->writeJsonFile($file, $session);
        }) ? true : false;
    }

    public function mutateSession($mutator) {
        $file = $this->getSessionFile();
        $store = $this;
        $result = null;
        $ok = $this->withNamedLock('session', function () use ($store, $file, $mutator, &$result) {
            $session = $store->loadSessionUnlocked();
            if ($session === false) {
                return false;
            }
            $out = call_user_func($mutator, $session);
            if (!is_array($out)) {
                return false;
            }
            if (isset($out['_session'])) {
                $session = $out['_session'];
                $result = $out;
                unset($result['_session']);
            } else {
                $session = $out;
                $result = $session;
            }
            if (!$store->writeJsonFile($file, $session)) {
                $store->lastError = 'Failed to write session file.';
                return false;
            }
            return true;
        });
        if ($ok === false) {
            return false;
        }
        return $result;
    }

    public function loadSessionUnlocked() {
        $file = $this->getSessionFile();
        if (!file_exists($file)) {
            return null;
        }
        $data = $this->readJsonFile($file);
        if ($data === false) {
            return false;
        }
        return is_array($data) ? $data : null;
    }

    public function initSession($rootDir, $reset = false) {
        if ($reset) {
            $this->resetSession();
        }

        $session = $this->loadSession();
        if ($session === false) {
            return false;
        }
        if ($session !== null) {
            return $session;
        }

        $session = $this->defaultSession($rootDir);
        if (!$this->saveSession($session)) {
            return false;
        }
        return $session;
    }

    public function resetSession() {
        $file = $this->getSessionFile();
        if (file_exists($file)) {
            @unlink($file);
        }
        $legacy = $this->dataDir . '/malware_scan_session.json';
        if (file_exists($legacy)) {
            @unlink($legacy);
        }
    }

    public function isTrusted($rawHash) {
        $knowledge = $this->loadKnowledge();
        if (!is_array($knowledge)) {
            return false;
        }
        return isset($knowledge['trusted'][$rawHash]);
    }

    public function getCandidate($rawHash) {
        $knowledge = $this->loadKnowledge();
        if (!is_array($knowledge)) {
            return null;
        }
        return isset($knowledge['candidates'][$rawHash]) ? $knowledge['candidates'][$rawHash] : null;
    }

    public function markClean($rawHash, $path, $scanSessionId) {
        $store = $this;
        $out = array('status' => 'error');
        $ok = $this->withNamedLock('knowledge', function () use ($store, $rawHash, $path, $scanSessionId, &$out) {
            $knowledge = $store->loadKnowledgeUnlocked();
            if (!is_array($knowledge)) {
                return false;
            }
            if (isset($knowledge['trusted'][$rawHash])) {
                $out = array('status' => 'already_trusted');
                return true;
            }
            if (isset($knowledge['candidates'][$rawHash])) {
                $cand = $knowledge['candidates'][$rawHash];
                $candPath = isset($cand['first_path']) ? $cand['first_path'] : '';
                $candSession = isset($cand['first_session_id']) ? $cand['first_session_id'] : '';
                if ($candPath !== $path || $candSession !== $scanSessionId) {
                    unset($knowledge['candidates'][$rawHash]);
                    $knowledge['trusted'][$rawHash] = array(
                        'clean_count' => 2,
                        'first_path'  => $candPath,
                        'second_path' => $path,
                        'trusted_at'  => time(),
                    );
                    if (!$store->writeJsonFile($store->getKnowledgeFile(), $knowledge)) {
                        return false;
                    }
                    $store->markSessionItemsTrusted($rawHash);
                    $out = array('status' => 'promoted_to_trusted');
                    return true;
                }
                $out = array('status' => 'candidate_already_recorded');
                return true;
            }

            $knowledge['candidates'][$rawHash] = array(
                'clean_count'      => 1,
                'first_path'       => $path,
                'first_session_id' => $scanSessionId,
                'first_at'         => time(),
            );
            if (!$store->writeJsonFile($store->getKnowledgeFile(), $knowledge)) {
                return false;
            }
            $out = array('status' => 'candidate_added');
            return true;
        });
        if ($ok === false) {
            return array('status' => 'error', 'message' => $this->lastError);
        }
        return $out;
    }

    public function markSessionItemsTrusted($rawHash) {
        $this->mutateSession(function ($session) use ($rawHash) {
            if (!is_array($session) || empty($session['infected_files'])) {
                return $session;
            }
            foreach ($session['infected_files'] as &$inf) {
                if (isset($inf['raw_sha256']) && $inf['raw_sha256'] === $rawHash) {
                    if (!isset($inf['status']) || $inf['status'] === 'FOUND' || $inf['status'] === 'AI_SKIPPED' || $inf['status'] === 'AI_ERROR' || $inf['status'] === 'AI_PROCESSING') {
                        $inf['status'] = 'TRUSTED_HIDDEN';
                    }
                }
            }
            unset($inf);
            return $session;
        });
    }

    public function revokeCandidate($rawHash) {
        $store = $this;
        $removed = false;
        $this->withNamedLock('knowledge', function () use ($store, $rawHash, &$removed) {
            $knowledge = $store->loadKnowledgeUnlocked();
            if (!is_array($knowledge) || !isset($knowledge['candidates'][$rawHash])) {
                return true;
            }
            unset($knowledge['candidates'][$rawHash]);
            $removed = true;
            return $store->writeJsonFile($store->getKnowledgeFile(), $knowledge);
        });
        return $removed;
    }

    public function revokeTrusted($rawHash) {
        $store = $this;
        $removed = false;
        $this->withNamedLock('knowledge', function () use ($store, $rawHash, &$removed) {
            $knowledge = $store->loadKnowledgeUnlocked();
            if (!is_array($knowledge) || !isset($knowledge['trusted'][$rawHash])) {
                return true;
            }
            unset($knowledge['trusted'][$rawHash]);
            $removed = true;
            return $store->writeJsonFile($store->getKnowledgeFile(), $knowledge);
        });
        return $removed;
    }

    public function getAiCache($cacheKey) {
        $knowledge = $this->loadKnowledge();
        if (!is_array($knowledge)) {
            return null;
        }
        if (isset($knowledge['ai_cache'][$cacheKey])) {
            return $knowledge['ai_cache'][$cacheKey];
        }
        return null;
    }

    public function setAiCache($cacheKey, $verdictData) {
        $store = $this;
        return $this->withNamedLock('knowledge', function () use ($store, $cacheKey, $verdictData) {
            $knowledge = $store->loadKnowledgeUnlocked();
            if (!is_array($knowledge)) {
                return false;
            }
            $knowledge['ai_cache'][$cacheKey] = $verdictData;
            return $store->writeJsonFile($store->getKnowledgeFile(), $knowledge);
        }) ? true : false;
    }

    public function clearAiCache() {
        $store = $this;
        return $this->withNamedLock('knowledge', function () use ($store) {
            $knowledge = $store->loadKnowledgeUnlocked();
            if (!is_array($knowledge)) {
                return false;
            }
            $knowledge['ai_cache'] = array();
            return $store->writeJsonFile($store->getKnowledgeFile(), $knowledge);
        }) ? true : false;
    }

    public function findInfected($session, $findingId) {
        if (!is_array($session) || empty($session['infected_files'])) {
            return null;
        }
        foreach ($session['infected_files'] as $idx => $inf) {
            if (isset($inf['finding_id']) && $inf['finding_id'] === $findingId) {
                return array('index' => $idx, 'item' => $inf);
            }
        }
        return null;
    }

    public function claimNextInfectedForAutoReview($jobId = '') {
        $store = $this;
        $claimed = null;
        $ok = $this->withNamedLock('session', function () use ($store, $jobId, &$claimed) {
            $session = $store->loadSessionUnlocked();
            if (!is_array($session) || empty($session['infected_files'])) {
                return true;
            }
            $now = time();
            $staleAfter = 90;
            $generation = isset($session['generation']) ? intval($session['generation']) : 1;
            foreach ($session['infected_files'] as $idx => $inf) {
                $status = isset($inf['status']) ? $inf['status'] : '';
                $claimedAt = isset($inf['ai_claimed_at']) ? intval($inf['ai_claimed_at']) : 0;
                $isFound = ($status === 'FOUND');
                $isStale = ($status === 'AI_PROCESSING' && ($claimedAt === 0 || ($now - $claimedAt) >= $staleAfter));
                if ($isFound || $isStale) {
                    $token = bin2hex(random_bytes(16));
                    $session['infected_files'][$idx]['status'] = 'AI_PROCESSING';
                    $session['infected_files'][$idx]['ai_claimed_at'] = $now;
                    $session['infected_files'][$idx]['claim_token'] = $token;
                    $session['infected_files'][$idx]['claim_generation'] = $generation;
                    if ($jobId !== '') {
                        $session['infected_files'][$idx]['claim_job'] = $jobId;
                    }
                    if (!$store->writeJsonFile($store->getSessionFile(), $session)) {
                        return false;
                    }
                    $claimed = array(
                        'index'      => $idx,
                        'item'       => $session['infected_files'][$idx],
                        'token'      => $token,
                        'generation' => $generation,
                    );
                    return true;
                }
            }
            return true;
        });
        if ($ok === false) {
            return false;
        }
        return $claimed;
    }

    public function updateInfectedItem($index, $updates, $token = null, $generation = null) {
        $store = $this;
        $updated = false;
        $ok = $this->withNamedLock('session', function () use ($store, $index, $updates, $token, $generation, &$updated) {
            $session = $store->loadSessionUnlocked();
            if (!is_array($session) || !isset($session['infected_files'][$index])) {
                return true;
            }
            $row = $session['infected_files'][$index];
            if ($generation !== null && isset($session['generation']) && intval($session['generation']) !== intval($generation)) {
                $store->lastError = 'Session generation mismatch.';
                return true;
            }
            if ($token !== null && (!isset($row['claim_token']) || !hash_equals((string)$row['claim_token'], (string)$token))) {
                $store->lastError = 'Claim token mismatch.';
                return true;
            }
            foreach ($updates as $k => $v) {
                $session['infected_files'][$index][$k] = $v;
            }
            if (!$store->writeJsonFile($store->getSessionFile(), $session)) {
                return false;
            }
            $updated = true;
            return true;
        });
        return $ok && $updated;
    }

    /**
     * Apply the terminal result of an auto-review claim.  The check and the
     * callback share the session lock so a cancel/restart cannot slip between
     * authorization and a filesystem side effect in the callback.
     *
     * The callback must not make a network request. It returns an array with an
     * `updates` array and may include a `result` array for its caller.
     */
    public function finishAutoReviewClaim($index, $token, $generation, $jobId, $callback) {
        $store = $this;
        $result = null;
        $ok = $this->withNamedLock('session', function () use ($store, $index, $token, $generation, $jobId, $callback, &$result) {
            $session = $store->loadSessionUnlocked();
            if (!is_array($session) || !isset($session['infected_files'][$index])) {
                $store->lastError = 'Auto-review finding is no longer available.';
                return false;
            }
            $job = isset($session['auto_review']) && is_array($session['auto_review'])
                ? $session['auto_review'] : self::defaultAutoReview();
            $row = $session['infected_files'][$index];
            if (
                !isset($session['generation']) || intval($session['generation']) !== intval($generation) ||
                !isset($job['status']) || $job['status'] !== 'running' ||
                !isset($job['job_id']) || !hash_equals((string)$job['job_id'], (string)$jobId) ||
                !isset($row['status']) || $row['status'] !== 'AI_PROCESSING' ||
                !isset($row['claim_token']) || !hash_equals((string)$row['claim_token'], (string)$token) ||
                !isset($row['claim_generation']) || intval($row['claim_generation']) !== intval($generation) ||
                !isset($row['claim_job']) || !hash_equals((string)$row['claim_job'], (string)$jobId)
            ) {
                $store->lastError = 'Auto-review claim is no longer current.';
                return false;
            }

            $out = call_user_func($callback);
            if (!is_array($out) || !isset($out['updates']) || !is_array($out['updates'])) {
                $store->lastError = 'Auto-review completion returned invalid updates.';
                return false;
            }
            $session['infected_files'][$index]['claim_token'] = '';
            $session['infected_files'][$index]['claim_job'] = '';
            $session['infected_files'][$index]['claim_generation'] = 0;
            $session['infected_files'][$index]['ai_claimed_at'] = 0;
            foreach ($out['updates'] as $key => $value) {
                $session['infected_files'][$index][$key] = $value;
            }
            if (!$store->writeJsonFile($store->getSessionFile(), $session)) {
                $store->lastError = 'Failed to save auto-review result.';
                return false;
            }
            $result = isset($out['result']) && is_array($out['result']) ? $out['result'] : array();
            return true;
        });
        return $ok ? $result : false;
    }

    public function autoReviewStats($session) {
        $stats = array(
            'pending'     => 0,
            'processing'  => 0,
            'skipped'     => 0,
            'cache_hits'  => 0,
            'failures'    => 0,
            'quarantined' => 0,
            'restored'    => 0,
            'trusted'     => 0,
            'found'       => 0,
        );
        if (!is_array($session) || empty($session['infected_files'])) {
            return $stats;
        }
        foreach ($session['infected_files'] as $inf) {
            $st = isset($inf['status']) ? $inf['status'] : '';
            if ($st === 'FOUND') {
                $stats['pending']++;
                $stats['found']++;
            } elseif ($st === 'AI_PROCESSING') {
                $stats['processing']++;
            } elseif ($st === 'AI_SKIPPED' || $st === 'CHANGED_SINCE_SCAN') {
                $stats['skipped']++;
            } elseif ($st === 'AI_ERROR' || $st === 'FAILED_DELETE') {
                $stats['failures']++;
            } elseif ($st === 'QUARANTINED' || $st === 'AI_QUARANTINED') {
                $stats['quarantined']++;
            } elseif ($st === 'RESTORED') {
                $stats['restored']++;
            } elseif ($st === 'TRUSTED_HIDDEN' || $st === 'TRUSTED') {
                $stats['trusted']++;
            }
            if (!empty($inf['ai_cache_hit'])) {
                $stats['cache_hits']++;
            }
        }
        $stats['hits'] = $stats['cache_hits'];
        $stats['errors'] = $stats['failures'];
        return $stats;
    }

    public function recordKeyCooldown($key, $duration = 60) {
        $fp = substr(hash('sha256', (string)$key), 0, 16);
        $until = time() + intval($duration);
        ZS_Config::$keyCooldowns[$key] = $until;
        $store = $this;
        return $this->withNamedLock('knowledge', function () use ($store, $fp, $until) {
            $k = $store->loadKnowledgeUnlocked();
            if (!is_array($k)) {
                return false;
            }
            if (!isset($k['key_cooldowns']) || !is_array($k['key_cooldowns'])) {
                $k['key_cooldowns'] = array();
            }
            $k['key_cooldowns'][$fp] = $until;
            return $store->writeJsonFile($store->getKnowledgeFile(), $k);
        }) ? true : false;
    }

    public function isKeyCooling($key) {
        if (isset(ZS_Config::$keyCooldowns[$key]) && time() < ZS_Config::$keyCooldowns[$key]) {
            return true;
        }
        $k = $this->loadKnowledge();
        if (!is_array($k) || empty($k['key_cooldowns']) || !is_array($k['key_cooldowns'])) {
            return false;
        }
        $fp = substr(hash('sha256', (string)$key), 0, 16);
        if (isset($k['key_cooldowns'][$fp])) {
            $until = intval($k['key_cooldowns'][$fp]);
            if (time() < $until) {
                ZS_Config::$keyCooldowns[$key] = $until;
                return true;
            }
        }
        return false;
    }
}
