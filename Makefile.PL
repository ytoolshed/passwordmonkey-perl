######################################################################
# Makefile.PL for PasswordMonkey
# 2011, Mike Schilli <cpan@perlmeister.com>
######################################################################
use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'         => 'PasswordMonkey',
    'VERSION_FROM' => 'lib/PasswordMonkey.pm', # finds $VERSION
    'PREREQ_PM'    => {
        Expect            => 1.21,
        Module::Pluggable => 3.9,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'lib/PasswordMonkey.pm',
       AUTHOR     => 'Mike Schilli <cpan@perlmeister.com>') : ()),
);
