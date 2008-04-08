use lib 'inc';
use ExtUtils::AutoInstall(
			  -core  => [ 'Carp'         => '0',
				      'IO::Socket'   => '0', 
				      'IO::Select'   => '0', 
				      'Time::HiRes'  => '0',
				      'Net::UCP::Common'             => '0',
				      'Net::UCP::IntTimeout'         => '0',
				      'Net::UCP::TransactionManager' => '0',]
			  );
WriteMakefile(
	      NAME              => 'Net::UCP',
	      VERSION_FROM      => 'lib/Net/UCP.pm', 
	      ($] >= 5.006 ?     
	       (ABSTRACT_FROM  => 'lib/Net/UCP.pm', 
		AUTHOR         => 'Marco Romano <nemux@cpan.org>') : ()),
	      );
