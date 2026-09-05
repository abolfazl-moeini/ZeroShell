<?php
/**
 * ZeroShell Build Script
 * Concatenates src/ files into a single drop-in malware-cleaner.php
 */

$root = dirname(dirname(__FILE__));
$distDir = $root . '/dist';
if (!is_dir($distDir)) {
    @mkdir($distDir, 0755, true);
}

$orderedFiles = array(
    'src/Hash.php',
    'src/Config.php',
    'src/I18n.php',
    'src/Rules.php',
    'src/Store.php',
    'src/Quarantine.php',
    'src/Engine.php',
    'src/Gemini.php',
    'src/Share.php',
    'src/Http.php',
    'src/Ui.php',
    'src/bootstrap.php',
);

$rulesJsonFile = $root . '/rules/database.json';
$rulesData = json_decode(file_get_contents($rulesJsonFile), true);
if (!$rulesData) {
    fwrite(STDERR, "Error: Invalid rules/database.json\n");
    exit(1);
}

$enI18n = include $root . '/src/i18n/en.php';
$faI18n = include $root . '/src/i18n/fa.php';
$css = file_get_contents($root . '/src/assets/app.css');
$js  = file_get_contents($root . '/src/assets/app.js');

$output = "<?php\n/**\n * ZeroShell WordPress Malware Scanner & Cleaner\n * Drop-in single-file security cleaner (PHP 7.4+)\n */\n\nif (!defined('ZS_INTERNAL')) { define('ZS_INTERNAL', true); }\n\n";

foreach ($orderedFiles as $relFile) {
    $fullPath = $root . '/' . $relFile;
    if (!file_exists($fullPath)) {
        fwrite(STDERR, "Error: Missing source file {$relFile}\n");
        exit(1);
    }

    $content = file_get_contents($fullPath);
    $content = preg_replace('/^\s*<\?php\s*/', '', $content);
    $content = preg_replace('/\?' . '>\s*$/', '', $content);

    if ($relFile === 'src/Rules.php') {
        $inlinedRules = "self::\$bundledCache = " . var_export($rulesData, true) . ";\n        return self::\$bundledCache;\n";
        $content = str_replace('// {{BUNDLED_RULES_DATA}}', $inlinedRules, $content);
    }

    if ($relFile === 'src/I18n.php') {
        $dictExport = "self::\$dictionaries = array(\n"
            . "            'en' => " . var_export($enI18n, true) . ",\n"
            . "            'fa' => " . var_export($faI18n, true) . ",\n"
            . "        );\n        return;\n";
        $content = str_replace('// {{INLINED_DICTIONARIES}}', $dictExport, $content);
    }

    if ($relFile === 'src/Ui.php') {
        $inlinedCss = "return " . var_export($css, true) . ";";
        $content = str_replace('// {{INLINED_CSS}}', $inlinedCss, $content);
        $inlinedJs = "return " . var_export($js, true) . ";";
        $content = str_replace('// {{INLINED_JS}}', $inlinedJs, $content);
    }

    $output .= "\n// --- BEGIN {$relFile} ---\n";
    $output .= $content;
    $output .= "\n// --- END {$relFile} ---\n";
}

$tmpFile = $distDir . '/malware-cleaner.php.tmp.' . bin2hex(random_bytes(4));
if (file_put_contents($tmpFile, $output) === false) {
    fwrite(STDERR, "Error: could not write temp artifact\n");
    exit(1);
}

exec('php -l ' . escapeshellarg($tmpFile), $lintOutput, $lintStatus);
if ($lintStatus !== 0) {
    fwrite(STDERR, "Lint failed; previous artifacts left unchanged.\n" . implode("\n", $lintOutput) . "\n");
    @unlink($tmpFile);
    exit(1);
}

$distFile = $distDir . '/malware-cleaner.php';
$rootFile = $root . '/malware-cleaner.php';
if (!@rename($tmpFile, $distFile)) {
    fwrite(STDERR, "Error: could not replace dist artifact\n");
    @unlink($tmpFile);
    exit(1);
}
if (!@copy($distFile, $rootFile)) {
    fwrite(STDERR, "Error: could not copy root artifact\n");
    exit(1);
}

$second = $distDir . '/malware-cleaner.php.check';
copy($distFile, $second);
if (md5_file($distFile) !== md5_file($rootFile)) {
    @unlink($second);
    fwrite(STDERR, "Error: dist and root artifacts differ\n");
    exit(1);
}
@unlink($second);

echo "Built successfully to:\n - {$distFile}\n - {$rootFile}\n";
echo "Syntax check OK (php -l clean)\n";
