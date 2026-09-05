<?php
class ZS_Hash {
    public static function raw($content) {
        return hash('sha256', $content);
    }

    public static function normalized($content) {
        $cleaned = preg_replace("#/\\*\\s*NIRMALA-HASH-PAD-START\\s*\\*/.*?/\\*\\s*NIRMALA-HASH-PAD-END\\s*\\*/\\s*#s", "", $content);
        $cleaned_norm = preg_replace("#const\\s+_[^\\s=]+\\s*=\\s*__FILE__;#", "", $cleaned);
        return hash('sha256', $cleaned_norm);
    }
}
