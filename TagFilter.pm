package HTML::TagFilter;
use strict;

use base qw(HTML::Parser);
use URI::Escape;

use vars qw($VERSION);

$VERSION = '0.091';

=head1 NAME

HTML::TagFilter - A fine-grained html-filter, xss-blocker and mailto-obfuscator

=head1 SYNOPSIS

    use HTML::TagFilter;
    my $tf = new HTML::TagFilter;
    my $clean_html = $tf->filter($dirty_html);
    
    # or
    
    my $tf = HTML::TagFilter->new(
        allow=>{...}, 
        deny=>{...}, 
        log_rejects => 1, 
        strip_comments => 1, 
        echo => 1,
        skip_xss_protection => 1,
        skip_ltgt_entification => 1,
        skip_mailto_entification => 1,
        xss_risky_attributes => [...],
        xss_permitted_protocols => [...],
        xss_allow_local_links => 1,
    );
    
    $tf->parse($some_html);
    $tf->parse($more_html);
    my $clean_html = $tf->output;
    my $cleaning_summary = $tf->report;
    my @tags_removed = $tf->report;
    my $error_log = $tf->error;

=head1 DESCRIPTION

HTML::TagFilter is a subclass of HTML::Parser with a single purpose: it will remove unwanted html tags and attributes from a piece of text. It can act in a more or less fine-grained way - you can specify permitted tags, permitted attributes of each tag, and permitted values for each attribute in as much detail as you like.

Tags which are not allowed are removed. Tags which are allowed are trimmed down to only the attributes which are allowed for each tag. It is possible to allow all or no attributes from a tag, or to allow all or no values for an attribute, and so on.

The filter will also guard against cross-site scripting attacks and obfuscate any mailto:email addresses, unless you tell it not to.

The original purpose for this was to screen user input. In that setting you'll often find that just using:

    my $tf = new HTML::TagFilter;
    put_in_database($tf->filter($my_text));

will do. However, it can also be used for display processes (eg text-only translation) or cleanup (eg removal of old javascript). In those cases you'll probably want to override the default rule set with a small number of denial rules. 

    my $self = HTML::TagFilter->new(deny => {img => {'all'}});
    print $tf->filter($my_text);

Will strip out all images, for example, but leave everything else untouched.

nb (faq #1) the filter only removes the tags themselves: all it does to text which is not part of a tag is to escape the <s and >s, to guard against false negatives and some common cross-site attacks.

=head1 CONFIGURATION: RULES

Creating the rule set is fairly simple. You have three options:

=head2 use the defaults

which will produce safe but still formatted html, without tables, javascript or much else apart from inline text formatting, links and images.

=head2 selectively override the defaults

use the allow_tags and deny_tags methods to pass in one or more additional tag settings. eg:

    $self->allow_tags({ p => { class=> ['lurid','sombre','plain']} });
    $self->deny_tags({ img => { all => [] });

will mean that all attributes other than class="lurid|sombre|plain" will be removed from <p> tags, but the other default rules will remain unchanged. See below for more about how to specify rules.

=head2 supply your own configuration

To override the defaults completely, supply the constructor with some rules:

    my $self = HTML::TagFilter->new( 
        allow=>{ p => { class=> ['lurid','sombre','plain']} }
    );

In this case only the rules you supply will be applied: the defaults are ignored. You can achieve the same thing after construction by first clearing the rule set:

    my $self = HTML::TagFilter->new();
    $self->clear_rules();
    $self->allow_tags({ p => { align=> ['left','right','center']} });

Future versions are intended to offer a more sophisticated rule system, allowing you to specify combinations of attributes, ranges for values and generally match names in a more fuzzy way.

=head1 CONFIGURATION: BEHAVIOURS

There are currently six switches that will change the behaviour of the filter. They're supplied at construction time alongside any rules you care to specify. All of them default to 'off':

  my $tf = HTML::TagFilter->new(
    log_rejects => 1,
    strip_comments => 1,
    echo => 1,
    skip_xss_protection => 1,
    skip_ltgt_entification => 1,
    skip_mailto_entification => 1,
  );
    
=over 4

=item log_rejects

Set log to something true and the filter will keep a detailed log of all the tags it removes. The log can be retrieved by calling report(), which will return a summary in scalar context and a detailed AoH in list.

=item echo

Set echo to 1, or anything true, and the output of the filter will be sent straight to STDOUT. Otherwise the filter is silent until you call output().

=item strip_comments

Set strip_comments to 1 and comments will be stripped. If you don't, they won't.

=item skip_xss_protection

Unless you set skip_xss_protection to 1, the filter will postprocess some of its output to protect against common cross-site scripting attacks. 

It will entify any < and > in non-tag text, entify quotes in attribute values (the Parser will have unencoded them) and strip out values for vulnerable attributes if they don't look suitably like urls. By default these attributes are checked: src, lowsrc, href, background and cite. You can replace that list (not extend it) at any time:

    $self->xss_risky_attributes( qw(your list of attributes) );

=item skip_ltgt_entification

Disables the entification of < and > even if cross-site protection is on.

=item skip_mailto_entification

Unless you specify otherwise, any mailto:url seen by the filter is completely turned into html entities. <a href="mailto:wross@cpan.org">will</a> becomes <a href="%6D%61%69%6C%74%6F%3A%77%72%6F%73%73%40%63%70%61%6E%2E%6F%72%67">will</a>

This should defeat most email-harvesting software, but note that it has no effect on the text of your link, only its address. Links like <a href="mailto:wross@cpan.org">wross@cpan.org</a> are only partly obscured.

=item other constructor parameters

You can also supply values that will be used as default values for the methods of the same name:

  xss_risky_attributes
  xss_permitted_protocols
  
each of which expects a list of strings, and 

  xss_allow_local_links

which wants a single true or false value.

=back

=head1 RULES

Each element is tested as it is encountered, in two stages:

=over 4

=item tag filter

Just checks that this tag is permitted, and blocks the whole thing if not. Applied to both opening and closing tags.

=item attribute filter

Any tag that passes the tag filter will remain in the text, but the attribute filter will strip out of it any attributes that are not permitted, or which have values that are not permitted for that tag/attribute combination.

=back

=head2 format for rules

There are two kinds of rule: permissions and denials. They work as you'd expect, and can coexist, but they're not quite symmetrical. Denial rules are intended to complement permission rules, so that they can provide a kind of compound 'unless'.

* If there are any 'permission' rules, then everything that doesn't satisfy any of them is eliminated.

* If there are any 'deny' rules, then anything that satisfies any of them is eliminated.

* If there are both denial and permission rules, then everything either satisfies a denial rule or fails to satisfy any of the permission rules is eliminated.

* If there is neither kind, we strip out everything just to be on the safe side.

The two most likely setups are 

1. a full set of permission rules and maybe a couple of denial rules to eliminate pet hates.

2. no permission rules at all and a small set of denial rules to remove particular tags.

Rules are passed in as a HoHoL:

    { tag name->{attribute name}->[valuelist] }

There are three reserved words: 'any and 'none' stand respectively for 'anything is permitted' and 'nothing is permitted', or if in denial: 'anything is removed' and 'nothing is removed'. 'all' is only used in denial rules and it indicates that the whole tag should be stripped out: see below for an explanation and some mumbled excuses.

For example:

    $self->allow_tags({ p => { any => [] });

Will permit <p> tags with any attributes. For clarity's sake it may be shortened to:

    $self->allow_tags({ p => { 'any' });

but note that you'll get a warning about the odd number of hash elements if -w is on, and in the absence of the => the quotes are required. And

    $self->allow_tags({ p => { none => [] });

Will allow <p> tags to remain in the text, but all attributes will be removed. The same rules apply at all levels in the tag/attribute/value hierarchy, so you can say things like:

    $self->allow_tags({ any => { align => [qw(left center right)] });
    $self->allow_tags({ p => { align => ['any'] });

=head2 examples

To indicate that a link destination is ok and you don't mind what value it takes:

    $self->allow_tags({ a => { 'href' } });

To limit the values an attribute can take:

    $self->allow_tags({ a => { class => [qw(big small middling)] } });

To clear all permissions:

    $self->allow_tags({});

To remove all onClicks from links but allow all targets:

    $self->allow_tags({ a => { onClick => ['none'], target => [], } });

You can combine allows and denies to create 'unless' rules:

    $self->allow_tags({ a => { any => [] } });
    $self->deny_tags({ a => { onClick => [] } });

Will remove only the onClick attribute of a link, allowing everything else through. If this was your only purpose, you could achieve the same thing just with the denial rule and an empty permission set, but if there's other stuff going on then you probably need this combination.

=head2 order of application

denial rules are applied first. we take out whatever you specify in deny, then take out whatever you don't specify in allow, unless the allow set is empty, in which case we ignore it. If both sets are empty, no tags gets through.

(We prefer to err on the side of less markup, but I expect this will be configurable soon.)

=head2 oddities

Only one deliberate one, so far. The main asymmetry between permission and denial rules is that from

    allow_tags->{ p => {...}}

it follows that p tags are permitted, but the reverse is not true: 

    deny_tags->{ p => {...}}

doesn't imply that p tags are removed, just that the relevant attributes are removed from them. If you want to use a denial rule to eliminate a whole tag, you have to say so explicitly:

    deny_tags->{ p => {'all'}}

will remove every <p> tag, whereas

    deny_tags->{ p => {'any'}}

will just remove all the attributes from <p> tags. Not very pretty, I know. It's likely to change, but probably not until after we've invented a system for supplying rules in a more readable format.

=cut

sub allowed_by_default {
	return {
		h1 => { none => [] },
		h2 => { none => [] },
		h3 => { none => [] },
		h4 => { none => [] },
		h5 => { none => [] },
		p => { none => [] },
		a => { href => [], name => [], target => [] },
		br => { clear => [qw(left right all)] },
		ul =>{ type => [] },
		li =>{ type => [] },
		ol => { none => [] },
		em => { none => [] },
		i => { none => [] },
		b => { none => [] },
		tt => { none => [] },
		pre => { none => [] },
		code => { none => [] },
		hr => { none => [] },
		blockquote => { none => [] },
		img => { src => [], height => [], width => [], alt => [], align => [] },
		any => { align => [qw(left right center)]  },
	};
}

sub denied_by_default {
	return {
		blink => { all => [] },
		marquee => { all => [] },
		any => { style => [], onMouseover => [], onClick => [], onMouseout => [], },
	};
}

sub new {
    my $class = shift;
    my $config = {@_};
    
    my $self = $class->SUPER::new(api_version => 3);

    $self->SUPER::handler(start => "filter_start", 'self, tagname, attr, attrseq');
    $self->SUPER::handler(end =>  "filter_end", 'self, tagname');
    $self->SUPER::handler(default => "clean_text", "self, text");
    $self->SUPER::handler(comment => "") if delete $config->{strip_comments};
	
    $self->{_allows} = {};
    $self->{_denies} = {};
    $self->{_settings} = {};
    $self->{_log} = ();
    $self->{_error} = ();

    $config->{allow} = allowed_by_default() unless $config->{allow} || $config->{deny};
    $config->{deny} = denied_by_default() unless $config->{allow} || $config->{deny};

    $self->allow_tags(delete $config->{allow});
    $self->deny_tags(delete $config->{deny});
    
    $self->{_settings}->{log} = 1 if delete $config->{log_rejects};
    $self->{_settings}->{echo} = 1 if delete $config->{echo};
    $self->{_settings}->{xss} = 1 unless delete $config->{skip_xss_protection};
    $self->{_settings}->{ltgt} = 1 unless delete $config->{skip_ltgt_entification};
    $self->{_settings}->{mailto} = 1 unless delete $config->{skip_mailto_entification};
    
    $self->_log_error("[warning] ignored unknown config field: $_") for keys %$config;
    
    return $self;
}

=head1 METHODS

=over 4

=item HTML::TagFilter->new();

If called without parameters, loads the default set. Otherwise loads the rules you supply. For the rule format, see above.

=item $tf->filter($html);

Exactly equivalent to:

    $tf->parse($html);
    $tf->output();

but more useful, because it'll fit in a oneliner. eg:

    print $tf->filter( $pages{$_} ) for keys %pages;
    
Note that calling filter() will clear anything that was waiting in the output buffer, and will clear the buffer again when it's finished. it's meant to be a one-shot operation and doesn't co-operate well. use parse() and output() if you want to daisychain.

=back

=cut

sub filter {
    my ($self, $text) = @_;
    $self->{output} = '';
    $self->parse($text);
    return $self->output unless $self->{_settings}->{echo};
}

=over 4

=item parse($text);

The parse method is inherited from HTML::Parser, but most of its normal behaviours are subclassed here and the output they normally print is kept for later. The other configuration options that HTML::Parser normally offers are not passed on, at the moment, nor can you override the handler definitions in this module.

=item output()

This will return and clear the output buffer. It will conclude the processing of your text, but you can of course pass a new piece of text to the same parser object and begin again.

=item report()

If called in list context, returns the array of rejected tag/attribute/value combinations. 

In scalar context returns a more or less readable summary. Returns () if logging not enabled. Clears the log.

=back

=cut

sub output {
    my $self = shift;
    $self->eof;
    my $output = $self->{output};
    $self->_log_error("[warning] no output from filter") unless $output;
    $self->{output} = '';
    return $output;
}

sub report {
    my $self = shift;
    return () unless defined $self->{_log};
    my @rejects = @{ $self->{_log} };
    $self->{_log} = ();
    return @rejects if wantarray;

    my $report = "the following tags and attributes have been stripped:\n";
    for (@rejects) {
        if ($_->{attribute}) {
            $report .= $_->{attribute} . '="' . $_->{value} . '" from the tag &lt;' . $_->{tag} . "&gt;";
            $report .= "(url disallowed)" if $_->{reason} eq 'url';
            $report .= "\n";
        } else {
            $report .= '&lt;' . $_->{tag} . "&gt;\n";
        }
    }
    return $report;
}

=over 4

=item filter_start($tag, $attributes_hashref, $attribute_sequence_listref);

This is the handler for html start tags: it checks the tag against the current set of rules, then checks each attribute and its value. Any text that fails is stripped out: the rest is passed to output.

=item filter_end($tag);

This is the handler for html end tags: it checks the tag against the current set of rules, and passes it to output if it's ok.

=item clean_text($text);

This is the handler for text: anything which is not tag is passed through here before being passed to output. At the moment it only applies some very simple cross-site protection: subclassing this method is an easy way to modify just the text part of your page.

=back

=cut

sub filter_start {
    my ($self, $tagname, $attributes, $attribute_sequence) = @_;
    return unless $self->tag_ok(lc($tagname));
    for (@$attribute_sequence) {
        my @data = (lc($tagname), lc($_), lc($attributes->{$_}));      # (tag, attribute, value)
        delete $attributes->{$_} unless $self->attribute_ok(@data) && $self->url_ok(@data);
    }
    my $surviving_attributes = join('', map { " $_=\"" . $self->_xss_clean_attribute($attributes->{$_}, $_) . '"' } grep { defined $attributes->{$_} } @$attribute_sequence);
    $self->add_to_output("<$tagname$surviving_attributes>");
}

sub filter_end {
    my ($self, $tagname) = @_;
    $self->add_to_output("</$tagname>") if $self->_tag_ok(lc($tagname));
}

sub clean_text {
    my ($self, $text) = @_;
    $self->add_to_output($self->_xss_clean_text($text));
}

sub _xss_clean_text {
    my ($self, $text) = @_;
    return $text unless $self->{_settings}->{xss};
    return $text unless $self->{_settings}->{ltgt};
    $text =~ s/>/&gt;/gs;
    $text =~ s/</&lt;/gs;
    return $text;
}

=over 4

=item add_to_output($text);

The supplied text is appended to the output buffer (or immediately printed, if echo is on).

=item logging($boolean);

This provides get-or-set access to the 'log' configuration parameter. Switching logging on or off during parsing will result in incomplete reports, of course.

=item log_denied($refused_tag);

If logging is on, this method will append the supplied failure information to the log. The standard form for this is a hashref that will contain some or all of these keys: 'tag', 'attribute', 'value' and 'reason'.

=back

=cut

sub add_to_output {
    my $self = shift;
    if ($self->{_settings}->{echo}) {
        print $_[0];
    } else {
        $self->{output} .= $_[0];
    }
}

sub logging {
    my $self = shift;
    $self->{_settings}->{log} = $_[0] if @_;
    return $self->{_settings}->{log};
}

sub log_denied {
    my ($self, $bad_tag) = @_;
    return unless $self->logging;
    push @{ $self->{_log} } , $bad_tag;
}

=over 4

=item tag_ok($tag);

Returns true if the supplied tag name is allowed in the text. If not, returns false and logs the failure with the reason 'tag'.

=item attribute_ok($tag, $attribute);

Returns true if it that attribute is allowed for that tag, and it is allowed to have the supplied value. If not, returns false and logs the failure with the reason 'attribute'.

=item url_ok($tag, $attributes, $value);

If xss protection is on, we check whether this attribute is a url field, and if it is we check that the url is a url (rather than a script tag or some other naughtiness). Failures are logged with the reason 'url'.

=back

=cut

sub tag_ok {
    my ($self, $tagname) = @_;
    my $ok = $self->_tag_ok($tagname);
    $self->log_denied({tag => $tagname, reason => 'tag' }) unless $ok;
    return $ok;
}

sub _tag_ok {
    my ($self, $tagname) = @_;
    return 0 unless $tagname && $self->has_rules;
    return 0 if $self->_check('_denies', 'attributes', $tagname, 'all');
    return 1 unless $self->has_allow_rules;
    return 1 if $self->_check('_allows', 'tags', $tagname);
    return 0;
}

sub attribute_ok {
    my ($self, $tagname, $attribute, $value) = @_;
    my $ok = $self->_attribute_ok( $tagname, $attribute, $value );
    $self->log_denied({ tag => $tagname, attribute => $attribute, value => $value, reason => 'attribute' }) unless $ok;
    return $ok;
}

sub _attribute_ok {
    my ($self, $tagname, $attribute, $value) = @_;
    return 0 unless $tagname && $attribute && $self->has_rules;
    return 0 if $self->_check('_denies','attributes', $tagname, 'any');
    return 0 if $self->_check('_denies','values', $tagname, 'all',);
    return 0 if $self->_check('_denies','values', $tagname, $attribute, 'any');
    return 0 if $self->_check('_denies','values', $tagname, $attribute, $value);
    return 1 unless $self->has_allow_rules;
    return 1 if $self->_check('_allows','attributes', $tagname, 'any');
    return 1 if $self->_check('_allows','values', 'any', $attribute, 'any');
    return 1 if $self->_check('_allows','values', 'any', $attribute, $value);
    return 1 if $self->_check('_allows','values', $tagname, $attribute, 'any');
    return 1 if $self->_check('_allows','values', $tagname, $attribute, $value);
    return 0;
}

sub url_ok {
    my ($self, $tagname, $attribute, $value) = @_;    
    my $ok = $self->_url_ok( $attribute, $value );
    $self->log_denied({ tag => $tagname, attribute => $attribute, value => $value, reason => 'url' }) unless $ok;
    return $ok;
}

sub _url_ok {
    my ($self, $attribute, $value) = @_;    
    return 1 unless $self->{_settings}->{xss};
	return 1 unless $self->_is_risky($attribute);
	return 1 if $self->xss_allow_local_links && $value =~ /^\//s || $value =~ /^\.\.\//s || $value !~ /:/s;
    return 1 if grep { $value =~ /^$_:/s } $self->xss_permitted_protocols;
    return 0;
}

# _xss_clean_attribute(): defends against very basic XSS attacks by entifying quote marks and <>

sub _xss_clean_attribute {
    my ($self, $text, $attribute) = @_;
    return $text unless $self->{_settings}->{xss};
	$text =~ s/"/&quot;/igs;
	$text =~ s/'/&rsquot;/igs;
    $text =~ s/>/&gt;/gs;
    $text =~ s/</&lt;/gs;
    return $self->_obfuscate_mailto($text) if $attribute eq 'href';
    return $text;
}

sub _is_risky {
    my ($self, $attribute) = @_;
    my %risky = map { $_ => 1 } $self->xss_risky_attributes;
    return $risky{$attribute};
}

# uri_escape is imported from URI::Escape

sub _obfuscate_mailto {
	my ($self, $address) = @_;
	return $address unless $self->{_settings}->{mailto};
	return $address unless $address =~ /^mailto:(.*)/;
	my $garbled = join '', map { uri_escape($_, "\0-\377") } split //, $1;
	return "mailto:$garbled";
}

# _check(): a private function to test for a value buried deep in a HoHoHo 
# without cluttering the place up with autovivification.

sub _check {
    my $self = shift;
    my $field = shift;
    my @russian_dolls = @_;
    unless (@russian_dolls) {
        $self->_log_error("[warning] _check: no keys supplied");
        return 0;
    }
    my $deepref = $self->{$field};
    for (@russian_dolls) {
        unless (ref $deepref eq 'HASH') {
            $self->_log_error("[error] _check: deepref not a hashref");
            return 0;
        }
        return 0 unless $deepref->{$_};
        $deepref = $deepref->{$_};
    }
    return 1;
}

=over 4

=item allow_tags($hashref)

Takes a hashref of permissions and adds them to what we already have, replacing at the tag level where rules are already defined. In other words, you can add a tag to the existing set, but to add an attribute to an existing tag you have to specify the whole set of attribute permissions.  

If no rules are sent (eg an empty hashref, or nothing at all, or a non-hashref) this clears the permission rule set.

=item deny_tags($hashref)

likewise but sets up (or clears) denial rules.

=item has_rules()

Returns true only if either allow or deny rules have been defined.

=item has_allow_rules()

Returns true if allow rules have been defined.

=item has_deny_rules()

Returns true if denial rules have been defined.

=item clear_rules()

Clears the entire rule set ready for the supply of a new set. A filter with no rules will clear everything, by the way.

=back

=cut

sub allow_tags {
    my ($self, $tagset) = @_;
    if ($tagset && ref $tagset eq 'HASH' && %$tagset) {
        $self->_configurise('_allows', $tagset);
    } else {
        $self->{_allows} = {};
    }
    return 1;
}

sub deny_tags {
    my ($self, $tagset) = @_;
    if ($tagset && ref $tagset eq 'HASH' && %$tagset) {
        $self->_configurise('_denies', $tagset);
    } else {
        $self->{_denies} = {};
    }
    return 1;
}

sub has_rules {
    my $self = shift;
    return 1 if $self->has_allow_rules || $self->has_deny_rules;
    return 0;
}

sub has_allow_rules {
    my $self = shift;
    return 1 if $self->{_allows} && %{ $self->{_allows} };
    return 0;
}

sub has_deny_rules {
    my $self = shift;
    return 1 if $self->{_denies} && %{ $self->{_denies} };
    return 0;
}

sub clear_rules {
    my $self = shift;
    $self->{_allows} = {};
    $self->{_denies} = {};
}

# _configurise(): a private function that translates input rules into
# the bushy HoHoHo's we're using for lookup.

sub _configurise {
    my ($self, $field, $tagset) = @_;

     unless (ref $tagset eq 'HASH') {
         $self->_log_error("[error] _configurise: supplied rules not a hashref");
         return ();
     }
     $self->_log_error("[warning] _configurise: supplied rule set empty") unless keys %$tagset;

    TAG: foreach my $tag (keys %$tagset) {
        $self->{$field}->{tags}->{$tag} = 1;
        
        ATT: foreach my $att (keys %{ $tagset->{$tag} }) {
			if ($att eq 'none') {
				$self->{$field}->{attributes}->{$tag} = {};
				next TAG;
			}
            $self->{$field}->{attributes}->{$tag}->{$att} = 1;
            $self->{$field}->{values}->{$tag}->{$att}->{any} = 1
            	unless defined( $tagset->{$tag}->{$att} ) && @{ $tagset->{$tag}->{$att} };
            foreach my $val (@{ $tagset->{$tag}->{$att} }) {
                $self->{$field}->{values}->{$tag}->{$att}->{$val} = 1;
            }
        }
    }
}

=over 4

=item allows()

Returns the full set of permissions as a HoHoho. Can't be set this way: ust a utility function in case you want to either display the rule set, or send it back to allow_tags in a modified form.

=item denies()

Likewise for denial rules.

=back

=cut

sub allows {
    my $self = shift;
    return $self->{_allows};
}

sub denies {
    my $self = shift;
    return $self->{_denies};
}

=over 4

=item xss_risky_attributes( @list_of_attributes );

Sets and returns a list of attributes that are considered to be urls, and should be checked for well-formedness. 

The default list is href, src, lowsrc, cite and background: any supplied values will be used to replace (not extend) this list.

=item xss_permitted_protocols( @list_of_prefixes );

Sets and returns a list of protocols that are acceptable in attributes that are considered to be urls. 

The default list is http, https, lowsrc and mailto. Any supplied values will be used to replace (not extend) this list. Don't include the colon.

=item xss_allow_local_links( $boolean );

If this method returns a true value, then addresses that begin '/' or '../' will be accepted in url fields. 

You can set this value by calling the method with a parameter, as usual. The default is true.

=back

=cut

sub xss_risky_attributes { 
    my $self = shift;
    return @{ $self->{_xss_att} } = @_ if @_;
    return @{ $self->{_xss_att} } if $self->{_xss_att};
    return @{ $self->{_xss_att} } = qw(src href cite lowsrc background) ;
}

sub xss_permitted_protocols { 
    my $self = shift;
    return @{ $self->{_xss_stems} } = @_ if @_;
    return @{ $self->{_xss_stems} } if $self->{_xss_stems};
    return @{ $self->{_xss_stems} } = qw(http https mailto ftp) ;
}

sub xss_allow_local_links { 
    my $self = shift;
    return $self->{_xss_local} = $_[0] if @_;
    return $self->{_xss_local} if $self->{_xss_local};
    return $self->{_xss_local} = 1;
}

=over 4

=item error()

Returns an error report of currently dubious usefulness.

=back

=cut

sub error {
    my $self = shift;
    return "HTML::TagFilter errors:\n" . join("\n", @{$self->{_error}}) if $self->{_error};
	return '';
}

# _log_error: append a message to the error log

sub _log_error {
    my $self = shift;
    push @{ $self ->{_error} } , @_;
}

# handler() exists here only to admonish people who try to use this module as they would
# HTML::Parser. The handler definitions in new() use SUPER::handler() to get around this.

sub handler {
    die("You can't set handlers for HTML::TagFilter. Perhaps you should be using HTML::Parser directly?");
}

sub version {
	return $VERSION;
}

1;

=head1 TO DO

More sanity checks on incoming rules

Simpler rule-definition interface

Complex rules. The long term goal is that someone can supply a rule like "remove all images where height or width is missing" or "change all font tags where size="2" to <span class="small">. Which will be hard. For a start, HTML::Parser doesn't see paired start and close tags, which would be required for conditional actions.

An option to speed up operations by working only at the tag level and using HTML::Parser's built-in screens.

=head1 REQUIRES

HTML::Parser

=head1 SEE ALSO

L<HTML::Parser>

=head1 AUTHOR

William Ross, wross@cpan.org

=head1 COPYRIGHT

Copyright 2001-3 William Ross

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

Please use https://rt.cpan.org/ to report bugs & omissions, describe cross-site attacks that get through, or suggest improvements.

=cut
