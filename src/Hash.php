<?php
class ZS_Hash {
    public static function raw($content) {
        return hash('sha256', (string)$content);
    }

    public static function rawFile($path) {
        if (!is_string($path) || $path === '' || is_link($path) || !is_file($path)) {
            return false;
        }
        $hash = @hash_file('sha256', $path);
        return is_string($hash) ? $hash : false;
    }

    public static function normalized($content) {
        $cleaned = preg_replace("#/\\*\\s*NIRMALA-HASH-PAD-START\\s*\\*/.*?/\\*\\s*NIRMALA-HASH-PAD-END\\s*\\*/\\s*#s", "", $content);
        $cleaned_norm = preg_replace("#const\\s+_[^\\s=]+\\s*=\\s*__FILE__;#", "", $cleaned);
        return hash('sha256', $cleaned_norm);
    }
}
