use lib 'inc';
use ExtUtils::AutoInstall(
			  -core  => [ 'Carp'         => '0',
				      'IO::Socket'   => '0', 
				      'IO::Select'   => '0', 
				      'Time::HiRes'  => '0' ]
			  );
WriteMakefile(
	      NAME              => 'Net::UCP',
	      VERSION_FROM      => 'lib/Net/UCP.pm', 
	      ($] >= 5.005 ?     
	       (ABSTRACT_FROM  => 'lib/Net/UCP.pm', 
		AUTHOR         => 'Marco Romano <nemux@cpan.org>') : ()),
	      );
