use Mozilla::Notifications::FNCrypto;
use Data::Dumper;

my $testPhrase = "This is a test of the emergency broadcasting service.";

my $fnc = new Mozilla::Notifications::FNCrypto();

my $kb = $fnc->generateKeyBundle();
print Dumper($kb);
my $block = $fnc->encrypt($testPhrase, $kb);

print Dumper($block);

my $response = $fnc->decrypt($block, $kb);
if ($response ne $testPhrase) {
    $DB::single=1;
    die "Error";
}
print "ok"

