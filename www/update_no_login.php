<?php

if (isset($_REQUEST['ip'])) {
    $IP = $_REQUEST['ip']
} else {
    $IP = $_SERVER['REMOTE_ADDR'];
}
$HOSTNAME = $_REQUEST['hostname'];

if (!isset($HOSTNAME)) {
    exit(1);
}

// Log to syslog.
openlog('pdns-update', null, LOG_USER);

try {
    $db = new PDO('sqlite:/var/lib/powerdns/pdns.sqlite3');
} catch(PDOException $e) {
    syslog(LOG_ALERT, 'Database error: ' . $e->getMessage());
    echo 'DB error!';
    exit(1);
}

$dbh = $db->prepare('SELECT content FROM records WHERE name=:name');
$dbh->bindparam(':name', $HOSTNAME);
$dbh->execute();
$dbr=$dbh->fetch(PDO::FETCH_LAZY);

if ($dbr['content'] !== $IP) {
    $dbh = $db->prepare('UPDATE records SET content=:content WHERE name=:name');
    // $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $dbh->bindparam(':content', $IP);
    $dbh->bindparam(':name', $HOSTNAME);
    $dbh->execute();

    syslog(LOG_INFO, "IP update for $HOSTNAME from {$dbr['content']} to $IP");

    updateSerial();
} else {
    syslog(LOG_DEBUG, "IP update attempt for $HOSTNAME. No update necessary.");
}
echo 'Success.';

// $dbh->debugDumpParams();

function updateSerial() {
    global $db;

    $dbh = $db->prepare("SELECT content FROM records WHERE type='SOA'");
    $dbh->setFetchMode(PDO::FETCH_ASSOC);
    $dbh->execute();
    $row = $dbh->fetch();

    if (!isset($row['content'])) {
        syslog(LOG_CRIT, 'No SOA record!');
        die;
    }

    preg_match('/([^\s]+) ([^\s]+) (\d+) (\d+) (\d+) (\d+) (\d+)/', $row['content'], $match);

    if (!isset($match[3])) {
        syslog(LOG_CRIT, "Unexpected SOA record format! [{$row['content']}]");
        die;
    }
    $dbh = $db->prepare("UPDATE records SET content=:content WHERE type='SOA'");
    $dbh->bindparam(':content', sprintf('%s %s %d %d %d %d %d', $match[1], $match[2],
        $match[3]+1, $match[4], $match[5], $match[6], $match[7]));
    $dbh->execute();
}
