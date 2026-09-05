<?php
class ZS_I18n {
    public static $activeLang = 'en';
    public static $dictionaries = null;

    public static function setLang($lang) {
        if ($lang === 'fa') {
            self::$activeLang = 'fa';
        } else {
            self::$activeLang = 'en';
        }
    }

    public static function getLang() {
        return self::$activeLang;
    }

    public static function isRtl() {
        return (self::$activeLang === 'fa');
    }

    public static function loadDictionaries() {
        if (self::$dictionaries !== null) {
            return;
        }

        // Placeholder for build-time inlining:
        // {{INLINED_DICTIONARIES}}
        $enFile = dirname(__FILE__) . '/i18n/en.php';
        $faFile = dirname(__FILE__) . '/i18n/fa.php';

        $en = file_exists($enFile) ? include $enFile : array();
        $fa = file_exists($faFile) ? include $faFile : array();

        self::$dictionaries = array(
            'en' => is_array($en) ? $en : array(),
            'fa' => is_array($fa) ? $fa : array(),
        );
    }

    public static function getDictionary($lang = null) {
        self::loadDictionaries();
        if ($lang === null) {
            $lang = self::$activeLang;
        }
        if (isset(self::$dictionaries[$lang])) {
            return self::$dictionaries[$lang];
        }
        return self::$dictionaries['en'];
    }

    public static function t($key, $vars = array()) {
        self::loadDictionaries();
        $dict = self::getDictionary(self::$activeLang);
        $text = null;

        if (isset($dict[$key])) {
            $text = $dict[$key];
        } elseif (isset(self::$dictionaries['en'][$key])) {
            $text = self::$dictionaries['en'][$key];
        } else {
            $text = $key;
        }

        if (!empty($vars) && is_array($vars)) {
            foreach ($vars as $k => $v) {
                $text = str_replace('{' . $k . '}', (string)$v, $text);
            }
        }

        return $text;
    }

    public static function getAll($lang = null) {
        return self::getDictionary($lang);
    }
}
