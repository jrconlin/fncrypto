use ExtUtils::MakeMaker;

$VERSION = "0.1";

WriteMakefile(
    NAME => "FNCrypto",
    VERSION => $VERSION,
    'PREREQ_PM' => {'Crypt::OpenSSL::AES' => '0.02'},
    'PM' => {
        'Mozilla/Notifications/FNCrypto.pm' =>
            '$(INST_LIBDIR)/Mozilla/Notifications/FNCrypto.pm',
        },
);


