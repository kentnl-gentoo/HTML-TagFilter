# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $loaded;}
use HTML::TagFilter;
$loaded = 1;
print "ok 1: module loaded\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

my $tf = new HTML::TagFilter(
	log_rejects => 1,
	strip_comments => 0,
	echo => 0,
);
my $result = $tf->filter("<p>testing</p>");
print ($result eq "<p>testing</p>" ? "ok 2: default allow\n" : "not ok 2\n");

$result = $tf->filter("<blink>testing</blink>");
print ($result eq "testing" ? "ok 3: default forbid tag\n" : "not ok 3\n");

$result = $tf->filter(qq|<p nonsense="rubbish">testing</p>|);
print ($result eq "<p>testing</p>" ? "ok 4: default forbid attribute\n" : "not ok 4\n");

$result = $tf->filter(qq|<p align="rubbish">testing</p>|);
print ($result eq "<p>testing</p>" ? "ok 5: default forbid value\n" : "not ok 5\n");

$tf->allow_tags();
$result = $tf->filter("<p>testing</p>");
print ($result eq "testing" ? "ok 6: change allow rule set\n" : "not ok 6\n");

$result = $tf->report;
print ($result =~ /&lt;p&gt;/ ? "ok 7: deletion report\n" : "not ok 7\n");

my $tf2 = new HTML::TagFilter(
	log_rejects => 0,
	strip_comments => 1,
	rubbish => 0,
);
$result = $tf2->error;
print ($result =~ /rubbish/ ? "ok 8: error report\n" : "not ok 8\n");

$result = $tf->filter("<p>testing</p><!--hey-->");
print ($result eq "testing&lt;!--hey--&gt;" ? "ok 9: comment permitted, < > escaped\n" : "not ok 9: $result\n");

$result = $tf2->filter("<p><blink>testing</blink></p><!--hey-->");
print ($result eq "<p>testing</p>" ? "ok 10: comment deleted\n" : "not ok 10\n");

$result = $tf2->report;
print ($result ? "not ok 11\n" : "ok 11: report empty\n");

my $tf3 = HTML::TagFilter->new( 
	allow => { p => { class=> [qw(lurid sombre plain)] } },
);
$result = $tf3->filter(qq|<p class="lurid"><b>testing</b></p>|);
print ($result eq qq|<p class="lurid">testing</p>| ? "ok 12: permitted attribute\n" : "not ok 12\n");

my $tf4 = HTML::TagFilter->new( 
	deny => { p => { any => [] } },
);
$result = $tf4->filter(qq|<p class="lurid"><b>testing</b></p>|);
print ($result eq qq|<p><b>testing</b></p>| ? "ok 13: forbidden attribute\n" : "not ok 13\n");




