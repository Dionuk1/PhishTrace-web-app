<?php
$file = __DIR__ . '/../includes/functions.php';
$lines = file($file);
$foundFirst = false;
$secondStart = 0;

foreach ($lines as $index => $line) {
    if (trim($line) === '<?php') {
        if (!$foundFirst) {
            $foundFirst = true;
        } else {
            $secondStart = $index;
            break;
        }
    }
}

if ($secondStart > 0) {
    $newLines = array_slice($lines, $secondStart);
    file_put_contents($file, implode('', $newLines));
    echo "Fixed! Skipped $secondStart lines.\n";
} else {
    echo "Could not find a second <?php tag.\n";
}
