#!/usr/bin/env perl
#
# 2wauth module for freeradius
#
# Copyright (C) 2015 Jeroen Nijhof <jeroen@jeroennijhof.nl>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# http://www.gnu.org/copyleft/gpl.html
#
use strict;
use Net::LDAP;
use Config::Simple;
use IO::Socket::INET;
use DBI;

use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG );

# constant definition for the remapping of return values
use constant RLM_MODULE_REJECT  =>  0; #  /* immediately reject the request */
use constant RLM_MODULE_FAIL    =>  1; #  /* module failed, don't reply */
use constant RLM_MODULE_OK      =>  2; #  /* the module is OK, continue */
use constant RLM_MODULE_HANDLED =>  3; #  /* the module handled the request, so stop. */
use constant RLM_MODULE_INVALID =>  4; #  /* the module considers the request invalid. */
use constant RLM_MODULE_USERLOCK => 5; #  /* reject the request (user is locked out) */
use constant RLM_MODULE_NOTFOUND => 6; #  /* user not found */
use constant RLM_MODULE_NOOP     => 7; #  /* module succeeded without doing anything */
use constant RLM_MODULE_UPDATED  => 8; #  /* OK (pairs modified) */
use constant RLM_MODULE_NUMCODES => 9; #  /* How many return codes there are */

our $ret_hash = { 
    0 => "RLM_MODULE_REJECT",
    1 => "RLM_MODULE_FAIL",
    2 => "RLM_MODULE_OK",
    3 => "RLM_MODULE_HANDLED",
    4 => "RLM_MODULE_INVALID", 
    5 => "RLM_MODULE_USERLOCK",
    6 => "RLM_MODULE_NOTFOUND",
    7 => "RLM_MODULE_NOOP",
    8 => "RLM_MODULE_UPDATED",
    9 => "RLM_MODULE_NUMCODES"
};

## constant definition for comparison
use constant false => 0;
use constant true  => 1;

## constant definitions for logging
use constant Debug => 1;
use constant Auth  => 2;
use constant Info  => 3;
use constant Error => 4;
use constant Proxy => 5;
use constant Acct  => 6;

## send_sms retries
use constant sms_retry => 5;

# Function to handle authenticate
sub authenticate {

    my $user = "";
    my $domain = "";
    my $password = "";
    if (exists($RAD_REQUEST{'User-Name'})) {
        $user = $RAD_REQUEST{'User-Name'};
    }
    if (exists($RAD_REQUEST{'User-Password'})) {
        $password = $RAD_REQUEST{'User-Password'};
    }
    my @tmp = split(/@/, $user);
    $domain = lc($tmp[1]);
    $user = lc($tmp[0]);

    my $dbh = db_init();
    if (!$dbh) {
        return RLM_MODULE_REJECT;
    }

    if (exists($RAD_REQUEST{'State'})) {
        &radiusd::radlog( Info, "$user\@$domain checking otp" );
        my $db_otp = db_get_otp($dbh, "$user\@$domain");
        db_close($dbh);

        if (index($password, $db_otp) != -1) {
            &radiusd::radlog( Info, "$user\@$domain otp successful" );
            $RAD_REPLY{'Reply-Message'} = "2wauth access granted";
            return RLM_MODULE_OK;
        }
        &radiusd::radlog( Info, "$user\@$domain otp failed" );
        $RAD_REPLY{'Reply-Message'} = "2wauth denied access!";
        return RLM_MODULE_REJECT;
    }

    my $conf = new Config::Simple('/etc/freeradius/2wauth.conf');
    my $ldap_conf = $conf->param(-block => $domain);
    my $ldap_server = $$ldap_conf{'ldap_server'};
    my $ldap_users = $$ldap_conf{'ldap_users'};
    my $ldap_group = $$ldap_conf{'ldap_group'};
    my $ldap_phone = $$ldap_conf{'ldap_phone'};

    my $ldap = Net::LDAP->new( $ldap_server );
    if (!$ldap) {
        &radiusd::radlog( Info, "Can't connect to ldap server, or domain name incorrect: $ldap_server" );
        $RAD_REPLY{'Reply-Message'} = "2wauth denied access!";
        db_close($dbh);
        return RLM_MODULE_REJECT;
    }
    $ldap->bind("$user\@$domain", password => $password);

    my $result = $ldap->search(
        base => $ldap_users,
        filter => "(&(sAMAccountName=$user)(memberOf=$ldap_group))",
        attrs => [$ldap_phone]
    );

    if ($result->code || $result->count == 0) {
        &radiusd::radlog(Info, "$user\@$domain authentication failed");
        $RAD_REPLY{'Reply-Message'} = "2wauth denied access!";
        db_close($dbh);
        return RLM_MODULE_REJECT;
    }

    my $otp = `/usr/bin/pwgen -A -0 -B 6 1`;
    chomp($otp);
    if (!db_rm_otp($dbh, "$user\@$domain")) {
        return RLM_MODULE_REJECT;
    }
    if (!db_add_otp($dbh, "$user\@$domain", $otp)) {
        return RLM_MODULE_REJECT;
    }

    my $phone = "0";
    foreach my $entry ($result->entries) {
        $phone = $entry->get_value($ldap_phone);
    }
    $ldap->unbind;

    &radiusd::radlog(Info, "$user\@$domain authenticated sending otp to $phone");
    my $response = send_sms($phone, "$domain\n\ncode: $otp");
    my $retry = 0;
    while (index($response, "ERROR") != -1) {
        $retry += 1;
        if ($retry > sms_retry) {
            &radiusd::radlog(Info, "Failed sending SMS");
            return RLM_MODULE_REJECT;
        }
        $response = send_sms($phone, "$domain\n\ncode: $otp");
    }

    $RAD_REPLY{'State'} = "SMS";
    $RAD_REPLY{'Reply-Message'} = "SMS has been sent";
    $RAD_CHECK{'Response-Packet-Type'} = "Access-Challenge";
    db_close($dbh);
    return RLM_MODULE_HANDLED;

}

# Function to handle authorize
sub authorize {

    return RLM_MODULE_OK;
}

# Function to handle preacct
sub preacct {

    return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {

    return RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {

    return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {

    return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {

    return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {

    return RLM_MODULE_OK;
}

# Function to handle detach
sub detach {

    # Do some logging.
    &radiusd::radlog( Info, "rlm_perl::Detaching. Reloading. Done." );
}

#
# Some functions that can be called from other functions
#

sub send_sms {
    my $eval = eval {
        local $SIG{ALRM} = sub { die 'timeout'; };
        alarm 10;
        my $pdu = sms($_[0], $_[1]);
        my $pdu_length = (length($pdu) - 2) / 2;
        my $socket = new IO::Socket::INET (
            PeerHost => '192.168.9.4',
            PeerPort => '4001',
            Proto => 'tcp',
        );
        return "ERROR" unless $socket;

        my $result;
        $socket->send("ATZ\r\n");
        $socket->recv($result, 1024);
        sleep(0.2);
        $socket->send("AT+CMGF=0\r\n");
        $socket->recv($result, 1024);
        sleep(0.2);
        $socket->send("AT+CMGS=$pdu_length\r\n");
        $socket->recv($result, 1024);
        sleep(0.2);
        $socket->send("$pdu\x1a\r\n");
        $socket->recv($result, 1024);
        $socket->close();
        alarm 0;
        return $result;
    };
    alarm 0;
    if ($eval) {
        return $eval;
    }
    return "ERROR";
}

sub handle_dbi_error {
    my $dbi_error = shift;
    &radiusd::radlog( Info, "DBI Error: $dbi_error" );
    return false;
}

sub db_init {
    my $driver = "SQLite";
    my $database = "/etc/freeradius/2wauth.db";
    my $dsn = "DBI:$driver:dbname=$database";
    my $userid = "";
    my $password = "";
    my $dbh = DBI->connect($dsn, $userid, $password, { RaiseError => 0 })
        or handle_dbi_error($DBI::errstr);

    my $stmt = qq(CREATE TABLE IF NOT EXISTS otp
        (username CHAR(64) PRIMARY KEY NOT NULL,
         otp CHAR(6) NOT NULL,
         timestamp DATETIME DEFAULT CURRENT_TIMESTAMP););
    my $rv = $dbh->do($stmt) or handle_dbi_error($DBI::errstr);
    return $dbh;
}

sub db_add_otp {
    my $dbh = $_[0];
    my $username = $_[1];
    my $otp = $_[2];
    my $stmt = qq(INSERT INTO otp (username, otp)
        VALUES ("$username", "$otp"););
    my $rv = $dbh->do($stmt) or handle_dbi_error($DBI::errstr);
}

sub db_rm_otp {
    my $dbh = $_[0];
    my $username = $_[1];
    my $stmt = qq(DELETE FROM otp WHERE username = "$username";);
    my $rv = $dbh->do($stmt) or handle_dbi_error($DBI::errstr);
}

sub db_get_otp {
    my $dbh = $_[0];
    my $username = $_[1];
    my $stmt = qq(SELECT otp FROM otp WHERE username = "$username";);
    my $sth = $dbh->prepare( $stmt );
    my $rv = $sth->execute() or handle_dbi_error($DBI::errstr);
    while(my @row = $sth->fetchrow_array()) {
        return $row[0];
    }
}

sub db_close {
    my $dbh = $_[0];
    $dbh->disconnect();
}

sub sms {
    my ($phonenumber, $data) = @_;

    my $pdu = '';
    my $pdutype = 0;	

    $pdu.='00';
	
    $pdutype=1;
    $pdu.=sprintf("%02x", $pdutype);
    $pdu.='00';				
    $pdu.=encodeDestinationAddress($phonenumber);
    $pdu.='00';

    # 7bit (00), 7biti/flash (F0)
    $pdu.='F0';

    $pdu.=sprintf("%.2X", length($data));
    $pdu.=encode_7bit(substr($data,0,160));
		
    return $pdu;
}

sub encodeDestinationAddress {
    my ($number) = @_;
    my $pdu;
	
    # Find type of phonenumber
    # no + => unknown number, + => international number
    my $type = (substr($number,0,1) eq '+')?'91':'81';
	
    # Delete any non digits => + etc...
    $number =~ s/\D//g;
	
    $pdu.= sprintf("%.2X%s",length($number),$type);
    $number.= "F";				# For odd number of digits
    while ($number =~ /^(.)(.)(.*)$/) {	# Get pair of digits
        $pdu.= "$2$1";
        $number = $3;
    }
    return $pdu;
}

sub encode_7bit {
    my ($msg) = @_;
    my ($bits, $ud, $octet);

    foreach (split(//,$msg)) {
        $bits .= unpack('b7', $_);
    }
    while (defined($bits) && (length($bits)>0)) {
        $octet = substr($bits,0,8);
        $ud .= unpack("H2", pack("b8", substr($octet."0" x 7, 0, 8)));
        $bits = (length($bits)>8)?substr($bits,8):"";
    }
    return uc $ud;
}

1;
