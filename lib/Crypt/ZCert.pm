package Crypt::ZCert;

use v5.10;
use Carp;
use strictures 1;

use FFI::Raw;

use Convert::Z85;
use Text::ZPL;

use Try::Tiny;

use List::Objects::WithUtils;

use List::Objects::Types  -types;
use Types::Path::Tiny     -types;
use Types::Standard       -types;

use Moo; use MooX::late;



has adjust_permissions => (
  is          => 'ro',
  isa         => Bool,
  builder     => sub { 1 },
);

has public_file => (
  lazy        => 1,
  is          => 'ro',
  isa         => Maybe[Path],
  coerce      => 1,
  predicate   => 1,
  builder     => sub { undef },
);

has secret_file => (
  lazy        => 1,
  is          => 'ro',
  isa         => Maybe[Path],
  coerce      => 1,
  predicate   => 1,
  builder     => sub {
    my ($self) = @_;
    $self->has_public_file ?
      $self->public_file . '_secret'
      : undef
  },
);


has public_key_z85 => (
  lazy        => 1,
  is          => 'ro',
  isa         => Str,
  predicate   => 1,
  writer      => '_set_public_key_z85',
  builder     => sub {
    my ($self) = @_;
    my $keypair = $self->generate_keypair;
    $self->_set_secret_key_z85( $keypair->secret );
    $keypair->public
  },
);

has secret_key_z85 => (
  lazy        => 1,
  is          => 'ro',
  isa         => Str,
  predicate   => 1,
  writer      => '_set_secret_key_z85',
  builder     => sub {
    my ($self) = @_;
    my $keypair = $self->generate_keypair;
    $self->_set_public_key_z85( $keypair->public );
    $keypair->secret
  },
);

has public_key => (
  lazy        => 1,
  is          => 'ro',
  isa         => Defined,
  builder     => sub { decode_z85( shift->public_key_z85 ) },
);

has secret_key => (
  lazy        => 1,
  is          => 'ro',
  isa         => Defined,
  builder     => sub { decode_z85( shift->secret_key_z85 ) },
);

has metadata => (
  lazy        => 1,
  is          => 'ro',
  isa         => HashObj,
  coerce      => 1,
  builder     => sub { +{} },
);

has _zmq_soname => (
  is          => 'ro',
  isa         => Str,
  builder     => sub {
    state $search = [ qw/
      libzmq.so.4
      libzmq.so.4.0.0
      libzmq.so.3
      libzmq.so
      libzmq.4.dylib
      libzmq.3.dylib
      libzmq.dylib
    / ];

    my ($soname, $zmq_vers);
    SEARCH: for my $maybe (@$search) {
      try {
        $zmq_vers = FFI::Raw->new(
          $maybe, zmq_version =>
            FFI::Raw::void,
            FFI::Raw::ptr,
            FFI::Raw::ptr,
            FFI::Raw::ptr,
        );
        $soname = $maybe;
      };
      last SEARCH if defined $soname;
    } # SEARCH
    croak "Failed to locate a suitable libzmq in your linker's search path"
      unless defined $soname;

    my ($maj, $min, $pat) = map {; pack 'i!', $_ } (0, 0, 0);
    $zmq_vers->(
      map {; unpack 'L!', pack 'P', $_ } $maj, $min, $pat
    );
    ($maj, $min, $pat) = map {; unpack 'i!', $_ } $maj, $min, $pat;
    unless ($maj >= 4) {
      my $vstr = join '.', $maj, $min, $pat;
      croak "This library requires ZeroMQ 4+ but you only have $vstr"
    }

    $soname
  },
);

has _zmq_errno => (
  lazy        => 1,
  is          => 'ro',
  isa         => Object,
  builder     => sub {
    FFI::Raw->new(
      shift->_zmq_soname, zmq_errno => FFI::Raw::int
    )
  },
);

has _zmq_strerr => (
  lazy        => 1,
  is          => 'ro',
  isa         => Object,
  builder     => sub {
    FFI::Raw->new(
      shift->_zmq_soname, zmq_strerror => FFI::Raw::str, FFI::Raw::int
    )
  },
);

sub _handle_zmq_error {
  my ($self, $rc) = @_;
  if ($rc == -1) {
    my $errno  = $self->_zmq_errno->();
    my $errstr = $self->_zmq_strerr->($errno);
    confess "libzmq zmq_curve_keypair failed: $errstr ($errno)"
  }
}

has _zmq_curve_keypair => (
  lazy        => 1,
  is          => 'ro',
  isa         => Object,
  builder     => sub {
    my ($self) = @_;
    FFI::Raw->new(
      $self->_zmq_soname, zmq_curve_keypair =>
        FFI::Raw::int,  # <- rc
        FFI::Raw::ptr,  # -> pub key ptr
        FFI::Raw::ptr,  # -> sec key ptr
    )
  },
);


sub BUILD {
  my ($self) = @_;
  $self->_read_cert;
}

sub _read_cert {
  my ($self) = @_;

  return unless $self->has_secret_file or $self->has_public_file;
  return unless $self->secret_file->exists;
    
  unless ($self->public_file->exists) {
    warn "Found 'secret_file' but not 'public_file': ".$self->public_file,
         " -- you may want to call a commit()"
  }

  my $secdata = decode_zpl( $self->secret_file->slurp );
  
  $secdata->{curve} ||= +{};
  my $pubkey = $secdata->{curve}->{'public-key'};
  my $seckey = $secdata->{curve}->{'secret-key'};
  unless ($pubkey && $seckey) {
    confess "Invalid ZCert; ".
      "expected 'curve' section containing 'public-key' & 'secret-key'"
  }
  $self->_set_public_key_z85($pubkey);
  $self->_set_secret_key_z85($seckey);
  $self->metadata->set(%{ $secdata->{metadata} }) if $secdata->{metadata};
}

sub generate_keypair {
  my ($self) = @_;

  # FIXME if POEx::ZMQ::FFI::Context is loaded, call ->generate_keypair there
  # instead?

  my ($pub, $sec) = (
    FFI::Raw::memptr(41), FFI::Raw::memptr(41)
  );

  $self->_handle_zmq_error(
    $self->_zmq_curve_keypair->($pub, $sec)
  );

  hash(
    public => $pub->tostr,
    secret => $sec->tostr,
  )->inflate
}

sub commit {
  my ($self) = @_;

  confess "commit() called but no public_file / secret_file set"
    unless $self->has_public_file
      and  $self->public_file
      and  $self->secret_file;

  my $data = +{
     curve    => +{
      'public-key' => $self->public_key_z85,
    },
    metadata => $self->metadata,
  };
  
  $self->public_file->spew( encode_zpl($data) );
  $data->{curve}->{'secret-key'} = $self->secret_key_z85;
  $self->secret_file->spew( encode_zpl($data) );
  $self->secret_file->chmod(0600) if $self->adjust_permissions;

  $data
}



1;

=pod

=head1 NAME

Crypt::ZCert - Manage ZeroMQ ZCert CURVE certificates

=head1 SYNOPSIS

  use Crypt::ZCert;

  my $zcert = Crypt::ZCert->new(
    public_file => "/foo/mycert",

    # Optionally specify a secret file not named "${public_file}_secret"
    # secret_file => "/foo/sekrit",
  );

  # Loaded from existing 'secret_file' if present,
  # generated via libzmq's zmq_curve_keypair(3) if not:
  my $pubkey = $zcert->public_key;
  my $seckey = $zcert->secret_key;

  # ... or as the original Z85:
  my $pubkey = $zcert->public_key_z85;
  my $seckey = $zcert->secret_key_z85;

  # Commit any freshly generated keys to disk
  # (as '/foo/mycert', '/foo/mycert_secret')
  # Without 'adjust_permissions => 0', _secret becomes chmod 0600:
  $zcert->commit;

=head1 DESCRIPTION

A module for creating & loading ZeroMQ "ZCert" files.

=head2 ATTRIBUTES

=head2 METHODS

=head1 AUTHOR

Jon Portnoy <avenj@cobaltirc.org>

=cut
