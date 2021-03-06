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
    $user = lc($tmp[0]);
    $domain = lc($tmp[1]);
    if ($domain eq '') {
        &radiusd::radlog( Info, "User login without domain" );
        $RAD_REPLY{'Reply-Message'} = "Please login with user\@domain";
        return RLM_MODULE_REJECT;
    }

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
            $RAD_REPLY{'Reply-Message'} = "Access granted";
            return RLM_MODULE_OK;
        }
        &radiusd::radlog( Info, "$user\@$domain otp failed" );
        $RAD_REPLY{'Reply-Message'} = "Access denied";
        return RLM_MODULE_REJECT;
    }

    my $conf = new Config::Simple('/etc/freeradius/2wauth.conf');
    if (!defined($conf)) {
        &radiusd::radlog( Info, "No domains found in config" );
        $RAD_REPLY{'Reply-Message'} = "No domains found in config";
        db_close($dbh);
        return RLM_MODULE_REJECT;
    }

    my $default_conf = $conf->param(-block => 'DEFAULT');
    my $ldap_conf = $conf->param(-block => $domain);
    my $ldap_server = $$ldap_conf{'ldap_server'};
    if ($ldap_server eq '') {
        $ldap_server = $$default_conf{'ldap_server'};
    }
    my $ldap_users = $$ldap_conf{'ldap_users'};
    if ($ldap_users eq '') {
        $ldap_users = $$default_conf{'ldap_users'};
    }
    my $ldap_group = $$ldap_conf{'ldap_group'};
    if ($ldap_group eq '') {
        $ldap_group = $$default_conf{'ldap_group'};
    }
    my $ldap_phone = $$ldap_conf{'ldap_phone'};
    if ($ldap_phone eq '') {
        $ldap_phone = $$default_conf{'ldap_phone'};
    }
    my $ldap_email = $$ldap_conf{'ldap_email'};
    if ($ldap_email eq '') {
        $ldap_email = $$default_conf{'ldap_email'};
    }

    my $ldap = Net::LDAP->new( $ldap_server );
    if (!$ldap) {
        &radiusd::radlog( Info, "Failed connecting to ldap server: $ldap_server" );
        $RAD_REPLY{'Reply-Message'} = "Failed connecting to ldap server";
        db_close($dbh);
        return RLM_MODULE_REJECT;
    }
    $ldap->bind("$user\@$domain", password => $password);

    if (substr($ldap_group, 0, 1) ne ':') {
        $ldap_group = "=".$ldap_group;
    }

    &radiusd::radlog( Info, "(&(sAMAccountName=$user)(memberOf$ldap_group))" );
    my $result = $ldap->search(
        base => $ldap_users,
        filter => "(&(sAMAccountName=$user)(memberOf$ldap_group))",
        attrs => [$ldap_phone, $ldap_email]
    );

    my $errcode = $result->code;
    if ($errcode || $result->count == 0) {
        &radiusd::radlog(Info, "Error code $errcode");
        &radiusd::radlog(Info, "$user\@$domain authentication failed");
        $RAD_REPLY{'Reply-Message'} = "Access denied";
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

    my $phone = '';
    my $email = '';
    foreach my $entry ($result->entries) {
        $phone = $entry->get_value($ldap_phone);
        $email = $entry->get_value($ldap_email);
    }
    $ldap->unbind;

    if ($phone ne '') {
        &radiusd::radlog(Info, "$user\@$domain authenticated sending otp to $phone");
        my $response = send_sms($phone, "$domain\n\ncode: $otp");
        my $retry = 0;
        while ($response != 0) {
            $retry += 1;
            &radiusd::radlog(Info, "Failed sending SMS, retrying");
            if ($retry > sms_retry) {
                &radiusd::radlog(Info, "Failed sending SMS");
                return RLM_MODULE_REJECT;
            }
            $response = send_sms($phone, "$domain\n\ncode: $otp");
        }
    }

    if ($email ne '') {
        &radiusd::radlog(Info, "$user\@$domain authenticated sending otp to $email");
        send_email($email, "code: $otp");
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

sub send_email {
    my $conf = new Config::Simple('/etc/freeradius/2wauth.conf');
    my $global_conf = $conf->param(-block => 'DEFAULT');
    my $from = $$global_conf{'email_from'};
    my $subject = $$global_conf{'email_subject'};
    my $email = $_[0];
    my $sms = $_[1];
    my $result = `echo $sms|/usr/bin/mail -r $from -s $subject $email`
}

sub send_sms {
    my $conf = new Config::Simple('/etc/freeradius/2wauth.conf');
    my $global_conf = $conf->param(-block => 'DEFAULT');
    my $server = $$global_conf{'sms_server'};
    my $key = $$global_conf{'sms_key'};
    my $phone = $_[0];
    my $sms = $_[1];
    return system("/usr/bin/curl --connect-timeout 5 -X POST -F 'key=$key' -F 'phone=$phone' -F 'message=$sms' http://$server/sms");
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

1;
