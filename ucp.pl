#!/usr/bin/perl

use lib 'lib/Net/';
use UCP;

$login = "login";
$password = "password";

#sent one message with send_sms();
###################################
$emi = Net::UCP->new(
		     SMSC_HOST   => 'ucp.example.com',
		     SMSC_PORT   => 6666,
		     );

$emi->open_link() or die ($!);

($acknowledge,$error_number,$error_text) = $emi->login(
						       SMSC_ID    => $login,
						       SMSC_PW    => $password,
						       );

($acknowledge,$error_number,$error_text) = $emi->send_sms(
							  RECIPIENT      => '00393001121',
							  MESSAGE_TEXT   => "Test Net::UCP",
							  SENDER_TEXT    => "NEMUX",
							  );
$emi->close_link();


#another message in RAW MODE
###############################

#INIT
$emi = Net::UCP->new(
		     SMSC_HOST   => 'ucp.example.com',
		     SMSC_PORT   => 5555,
		     SRC_HOST   => '10.0.10.1',
		     );

$emi->open_link() or die ($!);

#LOGIN
$ucp_string = $emi->make_message(
				 op => '60',
				 operation => 1,
				 styp => 1,         #open session
				 oadc => $login,
				 pwd  => $password,
				 vers => '0100',
				 );

if ( defined($ucp_string) ) {
    ($acknowledge, $error_number, $error_text) = $emi->transmit_msg( $ucp_string, 5, 1 );
    print $error_text ."\n";
} else {
    die "Error while making UCP String OP 60\n";
}

#SUBMIT MESSAGE
$ucp_string = $emi->make_message(
				 op => '51',
				 operation => 1,
				 adc   => '00393201001',
				 oadc  => 'ALPHA@NUM', 
				 mt   => 3,
				 amsg => 'Short Message for NEMUX by Net::UCP',
				 mcls => 1,
				 otoa => 5039,
				 );
if ( defined($ucp_string) ) {
    ($acknowledge, $error_number, $error_text) = $emi->transmit_msg( $ucp_string, 10, 1 );
    print $error_text ."\n";
} else {
    die "Error while making UCP String OP 51\n";
}

$emi->close_link();
