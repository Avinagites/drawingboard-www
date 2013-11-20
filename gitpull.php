<?php

echo getcwd() . "\n";
echo '<p>beginning git pull -u origin master...</p>';
echo shell_exec('/usr/bin/git pull -u origin master 2>&1');
echo '<p>done</p>';
?>