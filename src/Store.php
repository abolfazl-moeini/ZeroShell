<?php
class ZS_Store {
    private $dataDir;

    public function __construct($dataDir = null) {
        if ($dataDir === null) {
            $dataDir = ZS_Config::getDataDir();
        }
        $this->dataDir = $dataDir;
        ZS_Config::initDataDir($this->dataDir);
    }

    public function getSessionFile() {
        return $this->dataDir . '/malware_scan_session.json';
    }

    public function getKnowledgeFile() {
        return $this->dataDir . '/malware_cleaner_knowledge.json';
    }

    public function withLock($file, $mode, $callback) {
        $fp = @fopen($file, file_exists($file) ? 'c+' : 'w+');
        if (!$fp) {
            return false;
        }

        $lockMode = ($mode === 'write') ? LOCK_EX : LOCK_SH;
        if (!flock($fp, $lockMode)) {
            fclose($fp);
            return false;
        }

        $result = call_user_func($callback, $fp);

        flock($fp, LOCK_UN);
        fclose($fp);
        return $result;
    }

    public function loadKnowledge() {
        $file = $this->getKnowledgeFile();
        if (!file_exists($file)) {
            return $this->defaultKnowledge();
        }

        $content = @file_get_contents($file);
        $data = @json_decode($content, true);
        if (!is_array($data)) {
            return $this->defaultKnowledge();
        }

        return array_merge($this->defaultKnowledge(), $data);
    }

    private function defaultKnowledge() {
        return array(
            'schema_version' => 1,
            'trusted'        => array(),
            'candidates'     => array(),
            'ai_cache'       => array(),
        );
    }

    public function saveKnowledge($data) {
        $file = $this->getKnowledgeFile();
        return $this->withLock($file, 'write', function($fp) use ($data) {
            ftruncate($fp, 0);
            rewind($fp);
            $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            fwrite($fp, $json);
            fflush($fp);
            return true;
        });
    }

    public function loadSession() {
        $file = $this->getSessionFile();
        if (!file_exists($file)) {
            return null;
        }

        $content = @file_get_contents($file);
        $data = @json_decode($content, true);
        return is_array($data) ? $data : null;
    }

    public function saveSession($session) {
        $file = $this->getSessionFile();
        return $this->withLock($file, 'write', function($fp) use ($session) {
            ftruncate($fp, 0);
            rewind($fp);
            $json = json_encode($session, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            fwrite($fp, $json);
            fflush($fp);
            return true;
        });
    }

    public function initSession($rootDir, $reset = false) {
        if ($reset) {
            $this->resetSession();
        }

        $session = $this->loadSession();
        if ($session !== null) {
            return $session;
        }

        $sessionId = bin2hex(random_bytes(16));
        $session = array(
            'scan_session_id'  => $sessionId,
            'dir_queue'        => array($rootDir),
            'scanned_files'    => 0,
            'scanned_dirs'     => 0,
            'trusted_bypassed' => 0,
            'infected_files'   => array(),
            'start_time'       => time(),
            'is_completed'     => false,
            'current_dir'      => $rootDir,
        );

        $this->saveSession($session);
        return $session;
    }

    public function resetSession() {
        $file = $this->getSessionFile();
        if (file_exists($file)) {
            @unlink($file);
        }
    }

    public function isTrusted($normHash) {
        $knowledge = $this->loadKnowledge();
        return isset($knowledge['trusted'][$normHash]);
    }

    public function getCandidate($normHash) {
        $knowledge = $this->loadKnowledge();
        return isset($knowledge['candidates'][$normHash]) ? $knowledge['candidates'][$normHash] : null;
    }

    public function markClean($normHash, $path, $scanSessionId) {
        $file = $this->getKnowledgeFile();
        $store = $this;

        return $this->withLock($file, 'write', function($fp) use ($store, $normHash, $path, $scanSessionId) {
            rewind($fp);
            $content = stream_get_contents($fp);
            $knowledge = @json_decode($content, true);
            if (!is_array($knowledge)) {
                $knowledge = array(
                    'schema_version' => 1,
                    'trusted'        => array(),
                    'candidates'     => array(),
                    'ai_cache'       => array(),
                );
            }

            if (isset($knowledge['trusted'][$normHash])) {
                return array('status' => 'already_trusted');
            }

            if (isset($knowledge['candidates'][$normHash])) {
                $cand = $knowledge['candidates'][$normHash];
                $candPath = isset($cand['first_path']) ? $cand['first_path'] : '';
                $candSession = isset($cand['first_session_id']) ? $cand['first_session_id'] : '';

                if ($candPath !== $path || $candSession !== $scanSessionId) {
                    // Strike 2! Promote to trusted
                    unset($knowledge['candidates'][$normHash]);
                    $knowledge['trusted'][$normHash] = array(
                        'clean_count' => 2,
                        'first_path'  => $candPath,
                        'second_path' => $path,
                        'trusted_at'  => time(),
                    );

                    ftruncate($fp, 0);
                    rewind($fp);
                    fwrite($fp, json_encode($knowledge, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                    fflush($fp);

                    // Update infected items in current session
                    $store->markSessionItemsTrusted($normHash);

                    return array('status' => 'promoted_to_trusted');
                } else {
                    return array('status' => 'candidate_already_recorded');
                }
            }

            // First strike
            $knowledge['candidates'][$normHash] = array(
                'clean_count'      => 1,
                'first_path'       => $path,
                'first_session_id' => $scanSessionId,
                'first_at'         => time(),
            );

            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($knowledge, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            fflush($fp);

            return array('status' => 'candidate_added');
        });
    }

    public function markSessionItemsTrusted($normHash) {
        $file = $this->getSessionFile();
        if (!file_exists($file)) {
            return;
        }

        $this->withLock($file, 'write', function($fp) use ($normHash) {
            rewind($fp);
            $content = stream_get_contents($fp);
            $session = @json_decode($content, true);
            if (!is_array($session) || empty($session['infected_files'])) {
                return;
            }

            $changed = false;
            foreach ($session['infected_files'] as &$inf) {
                if (isset($inf['norm_sha256']) && $inf['norm_sha256'] === $normHash) {
                    if ($inf['status'] === 'FOUND') {
                        $inf['status'] = 'TRUSTED_HIDDEN';
                        $changed = true;
                    }
                }
            }

            if ($changed) {
                ftruncate($fp, 0);
                rewind($fp);
                fwrite($fp, json_encode($session, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                fflush($fp);
            }
        });
    }

    public function revokeCandidate($normHash) {
        $file = $this->getKnowledgeFile();
        return $this->withLock($file, 'write', function($fp) use ($normHash) {
            rewind($fp);
            $content = stream_get_contents($fp);
            $knowledge = @json_decode($content, true);
            if (!is_array($knowledge) || !isset($knowledge['candidates'][$normHash])) {
                return false;
            }

            unset($knowledge['candidates'][$normHash]);
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($knowledge, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            fflush($fp);
            return true;
        });
    }

    public function revokeTrusted($normHash) {
        $file = $this->getKnowledgeFile();
        return $this->withLock($file, 'write', function($fp) use ($normHash) {
            rewind($fp);
            $content = stream_get_contents($fp);
            $knowledge = @json_decode($content, true);
            if (!is_array($knowledge) || !isset($knowledge['trusted'][$normHash])) {
                return false;
            }

            unset($knowledge['trusted'][$normHash]);
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($knowledge, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            fflush($fp);
            return true;
        });
    }

    public function getAiCache($cacheKey) {
        $knowledge = $this->loadKnowledge();
        if (isset($knowledge['ai_cache'][$cacheKey])) {
            return $knowledge['ai_cache'][$cacheKey];
        }
        return null;
    }

    public function setAiCache($cacheKey, $verdictData) {
        $file = $this->getKnowledgeFile();
        return $this->withLock($file, 'write', function($fp) use ($cacheKey, $verdictData) {
            rewind($fp);
            $content = stream_get_contents($fp);
            $knowledge = @json_decode($content, true);
            if (!is_array($knowledge)) {
                $knowledge = array(
                    'schema_version' => 1,
                    'trusted'        => array(),
                    'candidates'     => array(),
                    'ai_cache'       => array(),
                );
            }

            $knowledge['ai_cache'][$cacheKey] = $verdictData;
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($knowledge, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            fflush($fp);
            return true;
        });
    }

    public function clearAiCache() {
        $file = $this->getKnowledgeFile();
        return $this->withLock($file, 'write', function($fp) {
            rewind($fp);
            $content = stream_get_contents($fp);
            $knowledge = @json_decode($content, true);
            if (!is_array($knowledge)) {
                return true;
            }

            $knowledge['ai_cache'] = array();
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($knowledge, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            fflush($fp);
            return true;
        });
    }

    public function claimNextInfectedForAutoReview() {
        $file = $this->getSessionFile();
        if (!file_exists($file)) {
            return null;
        }

        return $this->withLock($file, 'write', function($fp) {
            rewind($fp);
            $content = stream_get_contents($fp);
            $session = @json_decode($content, true);
            if (!is_array($session) || empty($session['infected_files'])) {
                return null;
            }

            $claimed = null;
            $claimedIdx = -1;
            $now = time();
            $staleAfter = 90;

            foreach ($session['infected_files'] as $idx => $inf) {
                $status = isset($inf['status']) ? $inf['status'] : '';
                $claimedAt = isset($inf['ai_claimed_at']) ? intval($inf['ai_claimed_at']) : 0;
                $isFound = ($status === 'FOUND');
                $isStale = ($status === 'AI_PROCESSING' && ($claimedAt === 0 || ($now - $claimedAt) >= $staleAfter));
                if ($isFound || $isStale) {
                    $claimed = $inf;
                    $claimedIdx = $idx;
                    $session['infected_files'][$idx]['status'] = 'AI_PROCESSING';
                    $session['infected_files'][$idx]['ai_claimed_at'] = $now;
                    break;
                }
            }

            if ($claimed !== null) {
                ftruncate($fp, 0);
                rewind($fp);
                fwrite($fp, json_encode($session, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                fflush($fp);
                return array('index' => $claimedIdx, 'item' => $claimed);
            }

            return null;
        });
    }

    public function updateInfectedItem($index, $updates) {
        $file = $this->getSessionFile();
        if (!file_exists($file)) {
            return false;
        }

        return $this->withLock($file, 'write', function($fp) use ($index, $updates) {
            rewind($fp);
            $content = stream_get_contents($fp);
            $session = @json_decode($content, true);
            if (!is_array($session) || !isset($session['infected_files'][$index])) {
                return false;
            }

            foreach ($updates as $k => $v) {
                $session['infected_files'][$index][$k] = $v;
            }

            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($session, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            fflush($fp);
            return true;
        });
    }
}
