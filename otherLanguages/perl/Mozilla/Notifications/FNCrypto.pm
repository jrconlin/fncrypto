# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

=pod
=head1 NAME 

Mozilla::Notifications::FNCrypto

=head1 SYNOPSIS

    my $fnc = new Mozilla::Notifications::FNCrypto();

    # The $keyBundle is provided by the userAgent as part of the permissions response.
    my $cryptContentString = encode_json({'title': 'Notification title',
                        'body': 'Notification message content',
                        'actionUrl': 'Notification Action URL'});

    my $cryptoBlock = $fnc->encrypt($cryptContentString, $keyBundle);

    $jsonBlock = {'title': 'Insecure Notification title',
                'time': $CurrentTime,
                'body': 'Unencrypted message content',
                'actionUrl': 'Insecure Notification URL',
                'cryptoBlock': $cryptoBlock);

    # ... send the $jsonBlock to the Notifications URL

=head1 DESCRIPTION

This library provides a simple perl encryption packager for Mozilla Notifications.
For more information, see https://wiki.mozilla.org/Services/Notifications

=cut

package Mozilla::Notifications::FNCrypto;


use 5;
use strict;
use warnings;

# Nettle does ecb, but this wrapper is a bit broken. If you're using
# libnettle3, you'll need to remove references to 
#   nettle_sha512
#   nettle_sha224
#   nettle_sha384
#   nettle_camellia*
# (yes, I will probably resubmit this back to cpan, eventually)
use Crypt::Nettle::Cipher;

use Digest::SHA;
use MIME::Base64;
use MIME::Base32;
use String::Random;
use Math::Random::Secure qw(irand);
use Data::Dumper;


our @ISA = qw(Exporter);
our %EXPORT_TAGS = ( 'all' => [ qw(
        )]);
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw(
);

our $VERSION = '0.01';

my $appName = 'fnCrypto';
my $HMAC_INPUT = $appName . '-AES_256_ECB-HMAC256';
my $bitSize = 256;
my %keyBundle;

sub new {
    my ($class, %args) = @_;
    my $self = {};
    bless $self, $class || 'FNCrypto';

    $self->init(%args);
    return $self;

}

sub randStringOfBits {
    my $self = shift;
    my $bitSize = shift || 256;
    my $result = '';
    for(my $b = 0; $b < $bitSize/8; $b++) {
        $result .= chr(irand(255));
    }
    return $result;
}

sub init {
    my $self = shift;

    my $rstr = new String::Random();
    my $bytes = $bitSize / 8;
    $self->{'syncKey'} = lc(MIME::Base32::encode($self->randStringOfBits()));
    $self->{'storage'} = {};
    $self->{'syncKey'} =~ tr/lo/89/;
}

sub toHex {
    my $self = shift;
    my $string = shift || $self;

    $string =~ s/(.)/sprintf('%02x', ord($1))/meg;
    return $string;
}

sub fromHex {
    my $self = shift;
    my $string = shift || $self;

    $string =~ s/(..)/chr(hex($1))/meg;
    return $string;
}

sub encrypt {
    my $self = shift;
    my $plainText = shift;
    my $keyBundle = shift;

    $DB::single=1;
    my $result = {};
    my $sha = Digest::SHA->new(256);
    $result->{'iv'} = MIME::Base64::encode($self->randStringOfBits(16 * 8));
    chomp ($result->{'iv'});
    $DB::single=1;
    my $key = $sha->reset()->add(
            toHex(fromHex($keyBundle->{'encryptionKey'}), 
            MIME::Base64::decode($result->{'iv'}))
        )->digest();
    my $aes = new Crypt::Nettle::Cipher('encrypt', 'aes256', $key, 'ecb');
    my $cryptText = "";
    for (my $b=0; $b < length($plainText);) {
        my $chunk = substr $plainText, $b, 16;
        $chunk .= "\0" x (16-length($chunk));
        $cryptText .= $aes->process($chunk);
        $b += 16;
    }
    $result->{'cipherText'} = MIME::Base64::encode($cryptText);
    chomp($result->{'cipherText'});
    $result->{'hmac'} = $sha->reset()->add(
        $keyBundle->{'hmac'},
        $result->{'cipherText'},
        $keyBundle->{'url'})->hexdigest();
    return $result;
}

sub decrypt {
    my $self = shift;
    my $cryptBlock = shift;    
    my $keyBundle = shift;

    my $sha = Digest::SHA->new(256);

    $DB::single=1;
    my $key = $sha->reset()->add(
            toHex(fromHex($keyBundle->{'encryptionKey'}), 
            MIME::Base64::decode($cryptBlock->{'iv'}))
        )->digest();
    my $aes = new Crypt::Nettle::Cipher('decrypt', 'aes256', $key, 'ecb');
    my $localHmac = $sha->reset()->add($keyBundle->{'hmac'},
        $cryptBlock->{'cipherText'},
        $keyBundle->{'url'})->hexdigest();
    if ($localHmac ne $cryptBlock->{'hmac'}) {
        die "EXCEPTION: Invalid HMAC";
    }
    my $plainText = "";
    my $cipherText = MIME::Base64::decode($cryptBlock->{'cipherText'});
    for (my $b=0; $b < length($cipherText);) {
        my $chunk = substr $cipherText, $b, 16;
        $chunk .= "\0" x (16-length($chunk));
        $plainText .= $aes->process($chunk);
        $b+=16;
    }
    print $plainText =~ s/\000//g;
    print Dumper($plainText);

    return $plainText;
}

#=== Support functions

sub getUserToken {
    my $self = shift;
    my $uid = shift || 0;

    return $self->{'storage'}->{$uid} || {'uid'=> $uid,
        'url'=> 'http://localhost'};
}

sub setUserToken {
    my $self = shift;
    my $uid = shift || 0;
    my $info = shift;

    $info->{'uid'} = $uid;
    $self->{'storage'}->{$uid} = $info;
    return $info;
}

sub generateKeyBundle {
    my $self = shift;
    my $uid = shift;

    my $sha = Digest::SHA->new(256);

    if (! defined $self->{'userToken'}) {
        $self->{'userToken'} = $self->getUserToken($uid);
    }
    if (! defined $uid) {
        $uid = $self->{'userToken'}->{'uid'};
    }
    $DB::single=1;
    $self->{'info'} = $HMAC_INPUT . $uid;
    $self->{'encryptionKey'} = $sha->add($self->{'syncKey'},
        $self->{'info'}, "\001")->hexdigest();
    my $hmac = $sha->reset()->add($self->{'encryptionKey'},
            $self->{'info'}, 
            "\002")->hexdigest();
    $self->{'keyBundle'} = {
        'encryptionKey' => $self->{'encryptionKey'},
        'hmac' => $hmac,
        'url' => "http://localhost"};
    $self->setUserToken($uid, $self->{'keyBundle'});
    return $self->{'keyBundle'};
}

sub getKeyBundle {
    my $self = shift;
    my $uid = shift;

    if ($self->{'keyBundle'}) {
        return $self->{'keyBundle'};
    }

    if ($self->{'storage'}->{$uid}) {
        return $self->{'storage'}->{$uid};
    }
    return $self->generateKeyBundle($uid);
}
1;
