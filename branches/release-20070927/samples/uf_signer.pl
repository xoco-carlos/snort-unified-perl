#!/usr/bin/perl -I..

use SnortUnified(qw(:DEFAULT :record_vars));
use Crypt::RSA;
use Digest::MD5 qw(md5 md5_base64);

$rsa = new Crypt::RSA;

$keyfile = shift || die("Usage: $0 <keyfile prefix> <unified file>\n");
$file = shift || die("Usage: $0 <keyfile prefix> <unified file>\n");
print("Enter password for provate key: "); $passwd = <STDIN>;
chomp $passwd;

$pubkey = new Crypt::RSA::Key::Public( Filename => "$keyfile.public");
$privkey = new Crypt::RSA::Key::Private( Filename => "$keyfile.private",
                                         Password => $passwd);
$debug = 0;
$UF_Data = {};
$record = {};
$logdata = undef;
$signature = undef;

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

if ( $UF_Data->{'TYPE'} eq 'LOG' ) {
    @fields = @$log_fields;
} else {
    @fields = @$alert_fields;
}

print("file,record");
foreach $field ( @fields ) {
    if ( $field ne 'pkt' ) { 
        print("," . $field);
    } else {
        print(",pktmd5,");
    }
}
print("recmd5\n");

$i = 1;
while ( $record = readSnortUnifiedRecord() ) {
    
    print($file . "," . $i++);;
    
    foreach $field ( @fields ) {
        if ( $field ne 'pkt' ) {
            print("," . $record->{$field});
        } else {
            print md5_base64($record->{$field}) . ",";
        }
    }
    print md5_base64($record->{'raw_record'});
    print("\n");

}

closeSnortUnified();

