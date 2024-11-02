<?php
$command = escapeshellcmd($_POST['command']);

$command = preg_replace('/(-o[NGOX])\s+(.+)/', '', $command);

$output = shell_exec($command);

if ($output === null) {
    http_response_code(500);
    echo "Error executing Nmap command: $command";
} else {
    echo $output;
}
?>