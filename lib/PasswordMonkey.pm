###########################################
package PasswordMonkey;
###########################################
use strict;
use warnings;
use Expect qw(exp_continue);
use Log::Log4perl qw(:easy);
use Module::Pluggable require => 1;

our $VERSION = "0.07";
our $PACKAGE = __PACKAGE__;

our $PASSWORD_MONKEY_OK      = 1;
our $PASSWORD_MONKEY_TIMEOUT = 2;

__PACKAGE__->make_accessor( $_ ) for qw(
expect
fills
is_success
timed_out
exit_status
);

###########################################
sub new {
###########################################
    my($class, %options) = @_;

    my $self = {
        expect        => Expect->new(),
        timeout       => 60,
        fillers       => [],
        filler_report => [],
        %options,
    };

    bless $self, $class;
}

###########################################
sub filler_add {
###########################################
    my($self, $filler) = @_;

    if( ! defined ref $filler or
        ! ref($filler) =~ /^$PACKAGE/ ) {
        LOGDIE "filler_add expects a filler object";
    }

    push @{ $self->{fillers} }, $filler;
}

###########################################
sub spawn {
###########################################
    my($self, $command, @parameters) = @_;

    DEBUG "Spawning $command @parameters";

    $self->{expect}->spawn($command, @parameters)
        or die "Cannot spawn $command: $!\n";
}

###########################################
sub go {
###########################################
    my($self) = @_;

    DEBUG "Monkey starts";

    my @regex_callbacks = ();

    $self->{fills}      = 0;
    $self->{is_success} = 1;
    $self->{timed_out}  = 0;
    $self->{eof}        = 0;

    for my $filler ( @{ $self->{ fillers } } ) {
        $filler->init();
        push @regex_callbacks, [ 
                $filler->prompt(),
                sub {
                    DEBUG "Running filler '", $filler->name(), "'";
                    for my $bouncer ( $filler->bouncers() ) {
                          # configure the bouncer object with
                          # the expect engine
                        $bouncer->init();
                        DEBUG "Running bouncer '", $bouncer->name(), "'\n";
                        $bouncer->expect( $self->{expect} );
                        if( $bouncer->check() ) {
                            DEBUG "Bouncer [", $bouncer->name(), 
                                  "] check succeeded";
                        } else {
                            ERROR "Bouncer [", $bouncer->name(), 
                                  "] check failed";
                              # continue without filling
                            return exp_continue;
                        }
                    }
                    $filler->pre_fill( @_ );
                    $filler->fill( @_ );
                    $filler->post_fill( @_ );

                    # reporting
                    push @{ $self->{filler_report} },
                         [ $self->expect->match, $filler->password ];
                
                    $self->{fills}++;
                    return exp_continue;
                }, $self];

       for my $dealbreaker ( @{ $filler->dealbreakers() } ) {
           my($pattern, $exit_code) = @$dealbreaker;
           push @regex_callbacks,
                [ $pattern, sub { 
                    DEBUG "Encountered dealbreaker [$pattern], exiting";
                    $self->{exit_status} = ($exit_code << 8);
                    $self->{is_success}  = 0;
                    # no exp_continue
                }];
       }
    }

    push @regex_callbacks, 
      [ "eof" => sub {
            DEBUG "Received 'eof'.";
            $self->{eof} = 1;
            return 0;
        }, $self 
      ],
      [ "timeout" => sub {
            ERROR "Received 'timeout'.";
            $self->{ is_success } = 0;
            $self->{ timed_out }  = 1;
            return 0;
        }, $self 
      ],
      ;

    my @expect_return =
      $self->{expect}->expect( $self->{timeout}, @regex_callbacks );

    for ( qw(matched_pattern_position
             error
             successfully_matching_string
             before_match
             after_match) ) {
        $self->{expect_return}->{$_} = shift @expect_return;
    }

      # Expect.pm sets the exit status *after* calling the 'eof' hook
      # defined above, so we need to do some post processing here.
    if( $self->{eof} ) {
        $self->{exit_status} = $self->{expect}->exitstatus();
        if( defined $self->{exit_status} ) {
            DEBUG "Exit status is $self->{exit_status}";
        } else {
            DEBUG "Exit status undefined";
        }
        if( !defined $self->{exit_status} or
            $self->{exit_status} != 0 ) {
            $self->{ is_success } = 0;
        }
    }

    DEBUG "Monkey stops (success=$self->{is_success})";
    return $self->{is_success};
}

##################################################
# Poor man's Class::Struct
##################################################
sub make_accessor {
##################################################
    my($package, $name) = @_;

    no strict qw(refs);

    my $code = <<EOT;
        *{"$package\\::$name"} = sub {
            my(\$self, \$value) = \@_;

            if(defined \$value) {
                \$self->{$name} = \$value;
            }
            if(exists \$self->{$name}) {
                return (\$self->{$name});
            } else {
                return "";
            }
        }
EOT
    if(! defined *{"$package\::$name"}) {
        eval $code or die "$@";
    }
}

1;

__END__

=head1 NAME

PasswordMonkey - Password prompt responder

=head1 SYNOPSIS

    use PasswordMonkey;

    my $sudo = PasswordMonkey::Filler::Sudo->new(
        password => "supersecrEt",
    );

    my $adduser = PasswordMonkey::Filler::Adduser->new(
        password => "logmein",
    );

    my $monkey = PasswordMonkey->new();

    $monkey->filler_add( $sudo );
    $monkey->filler_add( $adduser );

      # Spawn a script that asks for 
      #  - the sudo password and then
      #  - the new password for 'adduser' twice
    $monkey->spawn("sudo adduser testuser");

      # Password monkey goes to work
    $monkey->go();

    # ==== In action:
    # [sudo] password for mschilli: 
    # (waits two seconds)
    # ******** (types 'supersecrEt\n')
    # ...
    # Copying files from `/etc/skel' ...
    # Enter new UNIX password: 
    # ******** (types 'logmein')
    # Retype new UNIX password: 
    # ******** (types 'logmein')

=head1 DESCRIPTION

PasswordMonkey is a plugin-driven approach to provide passwords to prompts,
following strategies human users would employ as well. It comes with a set
of Filler plugins who know how to deal with common applications expecting 
password input (sudo, ssh) and a set of Bouncer plugins who know how to
employ different security strategies once a prompt has been detected.
It can be easily extended to support additional 
applications.

That being said, let me remind you that USING PLAINTEXT PASSWORDS IN 
AUTOMATED SYSTEMS IS ALMOST ALWAYS A BAD IDEA. Use ssh keys, custom
sudo rules, PAM modules, or other techniques instead. This Expect-based
module uses plain text passwords and it's useful in a context with legacy 
applications, because it provides a slightly better and safer mechanism 
than simpler Expect-based scripts, but it is still worse than using 
passwordless technologies. You've been warned.

=head1 Return Codes

The $monkey->go() method call returns a true value upon success, so running

    if( ! $monkey->go() ) {
        print "Something went wrong!\n";
    }

will catch any errors. Also, 

    $monkey->is_success();

will return true on success. Note that hitting a timeout or a bad exit
status of the spawned process is considered an error. To check for these
cases, use the following accessors:

    if( $monkey->exit_status() ) {
        print "The process exited with rc=", $monkey->exit_status(), "\n";
    }

    if( $monkey->timed_out() ) {
        print "The monkey timed out!\n";
    }

To get the number of password fills the monkey performed, use

    my $nof_fills = $monkey->fills();

Note that C<exit_status()> returns the Perl-specific return code of
C<system()>. If you need the shell-specific return code, you need to
use C<exit_status() E<gt>E<gt> 8> instead 
(check 'perldoc -f system' for details).

=head1 Fillers

=head2 PasswordMonkey::Filler::Sudo

Sudo passwords

Running a command like

    $ sudo adduser testuser
    [sudo] password for mschilli: 
    ********

=head2 PasswordMonkey::Filler::Passwd

The passwd Program

    Copying files from `/etc/skel' ...
    Enter new UNIX password: 
    ********
    Retype new UNIX password: 
    ********

=head2 PasswordMonkey::Filler::SSH

    $ ssh localhost
    testuser@localhost's password: 
    ********

=head1 Bouncer Plugins

Bouncer plugins can configure a number of security checks to run after
a prompt has been detected. These checks are also implemented as
plugins, and are added to filler plugins via their C<bouncer_add>
method.

=head2 Verifying inactivity after password prompts: Bouncer::Wait

To make sure that we are actually dealing with a sudo 
password prompt in the form of

    # [sudo] password for joeuser: 

and not just a fly-by text string matching the prompt regular expression,
we add a Wait Bouncer object to it, which blocks the Sudo plugin's response
until two seconds have passed without any other output, making sure
that the application is actually waiting for input:

    use PasswordMonkey;

    my $sudo = PasswordMonkey::Filler::Sudo->new(
        password => "supersecrEt",
    );

    my $wait_two_secs =
        PasswordMonkey::Bouncer::Wait->new( seconds => 2 );

    $sudo->bouncer_add( $wait_two_secs );

    $monkey->filler_add( $sudo );

    $monkey->spawn("sudo ls");

This will spawn sudo, detect if it's asking for the user's password by
matching its output against a regular expression, and, upon a match,
waits two seconds and proceeds only if there's no further output
activity until then.

=head2 Typing on terminals with echo on: Bouncer::NoEcho

PasswordMonkey starts typing innocuous characters after receiving
a password prompt like C<Password:> and checks if those characters
appear on the screen:

    Password: abc

If nothing is displayed, the prompt is okay and the user hits C<Backspace> 
to delete the test characters, followed by the real password and the
C<Return> key. If, on the other hand, characters start to show up on screen,
the password entering process is aborted immediately.

=head2 Hitting enter to see prompt reappear: Bouncer::Retry

To see if a password prompt is really genuine, PasswordMonkey hits enter and
verifies the prompt reappears:

    Password:
    Password:

before it starts typing the password.

=head2 Filler API

Writing new filler plugins is easy, see the sudo plugin as an example:

    package PasswordMonkey::Filler::Sudo;
    use strict;
    use warnings;
    use base qw(PasswordMonkey::Filler);
    
    sub prompt {
        return qr(^\[sudo\] password for [\w_]+:\s*$);
    }

All that's required is that you let your plugin inherit from the
PasswordMonkey::Filler base class and then override the C<prompt>
method to return a regular expression for the prompt upon which 
the plugin is supposed to send its password.

=over 4

=item C<new( key => value )>

Most plugins accept a 'password' option, to set the password they'll
transmit with once their internally configured prompt has been
detected.

=item C<prompt()>

Returns the regular expression that the plugin is waiting for
to respond with the password.

=back

=head2 Bouncer API

A Bouncer plugin defines a C<check()> method which uses the a 
reference to the Expect object to run its prompt verification tests.

=head1 AUTHOR

2011, Mike Schilli <cpan@perlmeister.com>

=head1 COPYRIGHT & LICENSE

Copyright (c) 2011 Yahoo! Inc. All rights reserved. The copyrights to 
the contents of this file are licensed under the Perl Artistic License 
(ver. 15 Aug 1997).

