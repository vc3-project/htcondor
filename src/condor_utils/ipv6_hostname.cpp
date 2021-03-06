#include "condor_common.h"
#include <set>
#include "MyString.h"
#include "condor_sockaddr.h"
#include "condor_netdb.h"
#include "condor_config.h"
#include "condor_sockfunc.h"
#include "ipv6_hostname.h"
#include "ipv6_addrinfo.h"
#include "my_hostname.h"

static condor_sockaddr local_ipaddr;
static condor_sockaddr local_ipv4addr;
static condor_sockaddr local_ipv6addr;
static MyString local_hostname;
static MyString local_fqdn;
static bool hostname_initialized = false;

static bool nodns_enabled()
{
	return param_boolean("NO_DNS", false);
}

#ifdef TEST_DNS_TODO
static void replace_higher_scoring_addr(const char * reason, condor_sockaddr & current, int & current_score,
	const condor_sockaddr & potential, int potential_score) {
	const char * result = "skipped for low score";
	if(current_score < potential_score) {
		current = potential;
		current_score = potential_score;
		result = "new winner";
	}

	dprintf(D_HOSTNAME, "%s: %s (score %d) %s\n",
		reason,
		potential.to_ip_string().Value(),
		potential_score,
		result);
}
#endif

bool init_local_hostname_impl()
{
	bool local_hostname_initialized = false;
	if (param(local_hostname, "NETWORK_HOSTNAME")) {
		local_hostname_initialized = true;
		dprintf(D_HOSTNAME, "NETWORK_HOSTNAME says we are %s\n", local_hostname.Value());
	}

	if( ! local_hostname_initialized ) {
		// [TODO:IPV6] condor_gethostname is not IPv6 safe. Reimplement it.
		char hostname[MAXHOSTNAMELEN];
		int ret = condor_gethostname(hostname, sizeof(hostname));
		if (ret) {
			dprintf(D_ALWAYS, "condor_gethostname() failed. Cannot initialize "
					"local hostname, ip address, FQDN.\n");
			return false;
		}
		local_hostname = hostname;
	}

	MyString test_hostname = local_hostname;

	bool local_ipaddr_initialized = false;
	bool local_ipv4addr_initialized = false;
	bool local_ipv6addr_initialized = false;

	MyString network_interface;
	if (param(network_interface, "NETWORK_INTERFACE")) {
		if(local_ipaddr_initialized == false &&
			local_ipaddr.from_ip_string(network_interface)) {
			local_ipaddr_initialized = true;
			if(local_ipaddr.is_ipv4()) { 
				local_ipv4addr = local_ipaddr;
				local_ipv4addr_initialized = true;
			}
			if(local_ipaddr.is_ipv6()) { 
				local_ipv6addr = local_ipaddr;
				local_ipv6addr_initialized = true;
			}
		}
	}

	if( ! local_ipaddr_initialized ) {
		std::string ipv4, ipv6, ipbest;
		if( network_interface_to_ip("NETWORK_INTERFACE", network_interface.Value(), ipv4, ipv6, ipbest, NULL)) {
			ASSERT(local_ipaddr.from_ip_string(ipbest));
			// If this fails, network_interface_to_ip returns something invalid.
			local_ipaddr_initialized = true;
		} else {
			dprintf(D_ALWAYS, "Unable to identify IP address from interfaces.  None match NETWORK_INTERFACE=%s. Problems are likely.\n", network_interface.Value());
		}
		if((!ipv4.empty()) && local_ipv4addr.from_ip_string(ipv4)) {
			local_ipv4addr_initialized = true;
			ASSERT(local_ipv4addr.is_ipv4());
		}
		if((!ipv6.empty()) && local_ipv6addr.from_ip_string(ipv6)) {
			local_ipv6addr_initialized = true;
			ASSERT(local_ipv6addr.is_ipv6());
		}
	}

	bool local_fqdn_initialized = false;
	if (nodns_enabled()) {
			// condor_gethostname() returns a hostname with
			// DEFAULT_DOMAIN_NAME. Thus, it is always fqdn
		local_fqdn = local_hostname;
		local_fqdn_initialized = true;
		if (!local_ipaddr_initialized) {
			local_ipaddr = convert_hostname_to_ipaddr(local_hostname);
			if (local_ipaddr != condor_sockaddr::null) {
				local_ipaddr_initialized = true;
			}
		}
	}

	addrinfo_iterator ai;

	if( ! nodns_enabled() ) {
		const int MAX_TRIES = 20;
		const int SLEEP_DUR = 3;
		bool gai_success = false;
		for(int try_count = 1; true; try_count++) {
			addrinfo hint = get_default_hint();
			hint.ai_family = AF_UNSPEC;
			int ret = ipv6_getaddrinfo(test_hostname.Value(), NULL, ai, hint);
			if(ret == 0) { gai_success = true; break; }
			if(ret != EAI_AGAIN ) {
				dprintf(D_ALWAYS, "init_local_hostname_impl: ipv6_getaddrinfo() could not look up '%s': %s (%d).  Error is not recoverable; giving up.  Problems are likely.\n", test_hostname.Value(), gai_strerror(ret), ret );
				gai_success = false;
				break;
			}

			dprintf(D_ALWAYS, "init_local_hostname_impl: ipv6_getaddrinfo() returned EAI_AGAIN for '%s'.  Will try again after sleeping %d seconds (try %d of %d).\n", test_hostname.Value(), SLEEP_DUR, try_count + 1, MAX_TRIES );
			if(try_count == MAX_TRIES) {
				dprintf(D_ALWAYS, "init_local_hostname_impl: ipv6_getaddrinfo() never succeeded. Giving up. Problems are likely\n");
				break;
			}
			sleep(SLEEP_DUR);
		}

		if(gai_success) {
			int local_hostname_desireability = 0;
#ifdef TEST_DNS_TODO
			int local_ipaddr_desireability = 0;
			int local_ipv4addr_desireability = 0;
			int local_ipv6addr_desireability = 0;
#endif
			while (addrinfo* info = ai.next()) {
				// TODO: the only time ai_canonname should be set is the first
				// record. Why are we testing its desirability?
				const char* name = info->ai_canonname;
				if (!name)
					continue;
				condor_sockaddr addr(info->ai_addr);

				int desireability = addr.desirability();

				const char * result = "skipped for low score";
				if(desireability > local_hostname_desireability) {
					result = "new winner";
					dprintf(D_HOSTNAME, "   I like it.\n");
					local_hostname_desireability = desireability;

					const char* dotpos = strchr(name, '.');
					if (dotpos) { // consider it as a FQDN
						local_fqdn = name;
						local_hostname = local_fqdn.Substr(0, dotpos-name-1);
					} else {
						local_hostname = name;
						local_fqdn = local_hostname;
						MyString default_domain;
						if (param(default_domain, "DEFAULT_DOMAIN_NAME")) {
							if (default_domain[0] != '.')
								local_fqdn += ".";
							local_fqdn += default_domain;
						}
					}
				}
				dprintf(D_HOSTNAME, "hostname: %s (score %d) %s\n", name, desireability, result);

#ifdef TEST_DNS_TODO
				// Resist urge to set local_ip*addr_initialized=true,
				// We want to repeatedly retest this looking for 
				// better results.
				if (!local_ipaddr_initialized) {
					replace_higher_scoring_addr("IP", 
						local_ipaddr, local_ipaddr_desireability, 
						addr, desireability);
				}

				if (addr.is_ipv4() && !local_ipv4addr_initialized) {
					replace_higher_scoring_addr("IPv4", 
						local_ipv4addr, local_ipv4addr_desireability, 
						addr, desireability);
				}

				if (addr.is_ipv6() && !local_ipv6addr_initialized) {
					replace_higher_scoring_addr("IPv6", 
						local_ipv6addr, local_ipv6addr_desireability, 
						addr, desireability);
				}
#else
	// Make Fedora quit complaining.
	if( local_ipv4addr_initialized && local_ipv6addr_initialized && local_fqdn_initialized ) {
		local_ipv4addr_initialized = false;
		local_ipv6addr_initialized = false;
		local_fqdn_initialized = false;
	}
#endif
			}
		}

	}

	return true;
}

void reset_local_hostname() {
	if( ! init_local_hostname_impl() ) {
		dprintf( D_ALWAYS, "Something went wrong identifying my hostname and IP address.\n" );
		hostname_initialized = false;
	} else {
		dprintf( D_HOSTNAME, "I am: hostname: %s, fully qualified doman name: %s, IP: %s, IPv4: %s, IPv6: %s\n", local_hostname.Value(), local_fqdn.Value(), local_ipaddr.to_ip_string().Value(), local_ipv4addr.to_ip_string().Value(), local_ipv6addr.to_ip_string().Value() );
		hostname_initialized = true;
	}
}

void init_local_hostname() {
	if( hostname_initialized ) { return; }
	reset_local_hostname();
}

condor_sockaddr get_local_ipaddr(condor_protocol proto)
{
	init_local_hostname();
	if ((proto == CP_IPV4) && local_ipv4addr.is_ipv4()) { return local_ipv4addr; }
	if ((proto == CP_IPV6) && local_ipv6addr.is_ipv6()) { return local_ipv6addr; }
	return local_ipaddr;
}

MyString get_local_hostname()
{
	init_local_hostname();
	return local_hostname;
}

MyString get_local_fqdn()
{
	init_local_hostname();
	return local_fqdn;
}

MyString get_fqdn_from_hostname(const MyString& hostname) {
	if (hostname.FindChar('.') != -1)
		return hostname;

	MyString ret;

	if (!nodns_enabled()) {
		addrinfo_iterator ai;
		int res  = ipv6_getaddrinfo(hostname.Value(), NULL, ai);
		if (res) {
			dprintf(D_HOSTNAME, "ipv6_getaddrinfo() could not look up %s: %s (%d)\n", 
				hostname.Value(), gai_strerror(res), res);
			return ret;
		}

		while (addrinfo* info = ai.next()) {
			if (info->ai_canonname) {
				if (strchr(info->ai_canonname, '.'))
					return info->ai_canonname;
			}
		}

		hostent* h = gethostbyname(hostname.Value());
		if (h && h->h_name && strchr(h->h_name, '.')) {
			return h->h_name;
		}
		if (h && h->h_aliases && *h->h_aliases) {
			for (char** alias = h->h_aliases; *alias; ++alias) {
				if (strchr(*alias, '.'))
					return *alias;
			}
		}
	}

	MyString default_domain;
	if (param(default_domain, "DEFAULT_DOMAIN_NAME")) {
		ret = hostname;
		if (ret[ret.Length() - 1] != '.')
			ret += ".";
		ret += default_domain;
	}
	return ret;
}

int get_fqdn_and_ip_from_hostname(const MyString& hostname,
		MyString& fqdn, condor_sockaddr& addr) {

	MyString ret;
	condor_sockaddr ret_addr;
	bool found_ip = false;

	// if the hostname contains dot, hostname is assumed to be full hostname
	if (hostname.FindChar('.') != -1) {
		ret = hostname;
	}

	if (nodns_enabled()) {
		// if nodns is enabled, convert hostname to ip address directly
		ret_addr = convert_hostname_to_ipaddr(hostname);

		// note that convert_hostname_to_ipaddr() could fail; if so,
		// leave found_ip = false and fall through to the block below
		// where we try to use the resolver.
		if (ret_addr != condor_sockaddr::null) {
			found_ip = true;
		}
	}

	if (!found_ip) {
		// we look through getaddrinfo and gethostbyname
		// to further seek fully-qualified domain name and corresponding
		// ip address
		addrinfo_iterator ai;
		int res  = ipv6_getaddrinfo(hostname.Value(), NULL, ai);
		if (res) {
			dprintf(D_HOSTNAME, "ipv6_getaddrinfo() could not look up %s: %s (%d)\n", hostname.Value(),
				gai_strerror(res), res);
			return 0;
		}

		while (addrinfo* info = ai.next()) {
			if (info->ai_canonname) {
				fqdn = info->ai_canonname;
				addr = condor_sockaddr(info->ai_addr);
				return 1;
			}
		}

		hostent* h = gethostbyname(hostname.Value());
		if (h && h->h_name && strchr(h->h_name, '.')) {
			fqdn = h->h_name;
			addr = condor_sockaddr((sockaddr*)h->h_addr);
			return 1;
		}
		if (h && h->h_aliases && *h->h_aliases) {
			for (char** alias = h->h_aliases; *alias; ++alias) {
				if (strchr(*alias, '.')) {
					fqdn = *alias;
					addr = condor_sockaddr((sockaddr*)h->h_addr);
					return 1;
				}
			}
		}
	}

	MyString default_domain;

	// if FQDN is still unresolved, try DEFAULT_DOMAIN_NAME
	if (ret.Length() == 0 && param(default_domain, "DEFAULT_DOMAIN_NAME")) {
		ret = hostname;
		if (ret[ret.Length() - 1] != '.')
			ret += ".";
		ret += default_domain;
	}

	if (ret.Length() > 0 && found_ip) {
		fqdn = ret;
		addr = ret_addr;
		return 1;
	}
	return 0;
}

MyString get_hostname(const condor_sockaddr& addr) {
	MyString ret;
	if (nodns_enabled())
		return convert_ipaddr_to_hostname(addr);

	condor_sockaddr targ_addr;

	// just like sin_to_string(), if given address is 0.0.0.0 or equivalent,
	// it changes to local IP address.
	if (addr.is_addr_any())
		targ_addr = get_local_ipaddr(addr.get_protocol());
	else
		targ_addr = addr;

	int e;
	char hostname[NI_MAXHOST];

	// if given address is link-local IPv6 address, it will have %NICname
	// at the end of string
	// we would like to avoid it
	if (targ_addr.is_ipv6())
		targ_addr.set_scope_id(0);

	e = condor_getnameinfo(targ_addr, hostname, sizeof(hostname), NULL, 0, 0);
	if (e)
		return ret;

	ret = hostname;
	return ret;
}

// will this work for ipv6?
// 1) maybe... even probably.
// 2) i don't care

bool verify_name_has_ip(MyString name, condor_sockaddr addr){
	std::vector<condor_sockaddr> addrs;

	addrs = resolve_hostname(name);
	if (IsDebugVerbose(D_SECURITY)) {
		// print the list of addrs that we are comparing against
		MyString ips_str; ips_str.reserve_at_least(addrs.size()*40);
		for(unsigned int i = 0; i < addrs.size(); i++) {
			ips_str += "\n\t";
			ips_str += addrs[i].to_ip_string().Value();
		}
		dprintf(D_SECURITY|D_VERBOSE, "IPVERIFY: checking %s against %s addrs are:%s\n",
				name.Value(), addr.to_ip_string().Value(), ips_str.Value());
	}
	for(unsigned int i = 0; i < addrs.size(); i++) {
		// compare MyStrings
		// addr.to_ip_string
		if(addrs[i].to_ip_string() == addr.to_ip_string()) {
			dprintf(D_SECURITY, "IPVERIFY: for %s matched %s to %s\n", name.Value(), addrs[i].to_ip_string().Value(), addr.to_ip_string().Value());
			return true;
		}
	}
	return false;
}

std::vector<MyString> get_hostname_with_alias(const condor_sockaddr& addr)
{
	std::vector<MyString> prelim_ret;
	std::vector<MyString> actual_ret;

	MyString hostname = get_hostname(addr);
	if (hostname.IsEmpty())
		return prelim_ret;

	// we now start to construct a list (prelim_ret) of the hostname and all
	// the aliases.  first the name itself.
	prelim_ret.push_back(hostname);

	if (nodns_enabled())
		// don't need to verify this... the string is actually an IP here
		return prelim_ret; // no need to call further DNS functions.

	// now, add the aliases

	hostent* ent;
		//int aftype = addr.get_aftype();
		//ent = gethostbyname2(hostname.Value(), addr.get_aftype());

		// really should call gethostbyname2() however most platforms do not
		// support. (Solaris, HP-UX, IRIX)
		// complete DNS aliases can be only obtained by gethostbyname.
		// however, what happens if we call it in IPv6-only system?
		// can we get DNS aliases for the hostname that only contains
		// IPv6 addresses?
	ent = gethostbyname(hostname.Value());

	if (ent) {
		char** alias = ent->h_aliases;
		for (; *alias; ++alias) {
			prelim_ret.push_back(MyString(*alias));
		}
	}

	// WARNING! there is a reason this is implimented as two separate loops,
	// so please don't try to combine them.
	//
	// calling verify_name_has_ip() will potentially overwrite static data that
	// is referred to by ent->h_aliases (man 3 gethostbyname, see notes).  so
	// first, we push the name and then all aliases into the MyString vector
	// prelim_ret, and then verify them in the following loop.

	for (unsigned int i = 0; i < prelim_ret.size(); i++) {
		if(verify_name_has_ip(prelim_ret[i], addr)) {
			actual_ret.push_back(prelim_ret[i]);
		} else {
			dprintf(D_ALWAYS, "WARNING: forward resolution of %s doesn't match %s!\n",
					prelim_ret[i].Value(), addr.to_ip_string().Value());
		}
	}

	return actual_ret;
}

// look up FQDN for hostname and aliases.
// if not, it adds up DEFAULT_DOMAIN_NAME
MyString get_full_hostname(const condor_sockaddr& addr)
{
		// this function will go smooth even with NODNS.
	MyString ret;
	std::vector<MyString> hostnames = get_hostname_with_alias(addr);
	if (hostnames.empty()) return ret;
	std::vector<MyString>::iterator iter;
	for (iter = hostnames.begin(); iter != hostnames.end(); ++iter) {
		MyString& str = *iter;
		if (str.FindChar('.') != -1) {
			return str;
		}
	}

	MyString default_domain;
	if (param(default_domain, "DEFAULT_DOMAIN_NAME")) {
			// first element is the hostname got by gethostname()
		ret = *hostnames.begin();
		if (default_domain[0] != '.')
			ret += ".";
		ret += default_domain;
	}
	return ret;
}

std::vector<condor_sockaddr> resolve_hostname(const char* hostname)
{
	MyString host(hostname);
	return resolve_hostname(host);
}


std::vector<condor_sockaddr> resolve_hostname(const MyString& hostname)
{
	std::vector<condor_sockaddr> ret;
	if (nodns_enabled()) {
		condor_sockaddr addr = convert_hostname_to_ipaddr(hostname);
		if (addr == condor_sockaddr::null)
			return ret;
		ret.push_back(addr);
		return ret;
	}
	return resolve_hostname_raw(hostname);
}

std::vector<condor_sockaddr> resolve_hostname_raw(const MyString& hostname) {
	//
	// For now, we can just document that you need the Punycoded DSN name.
	// If somebody complains about that, we can revisit this.  (If we
	// assume/require UTF-8 (int the config file), we can still readily
	// distinguish Sinfuls, since ':' and '?' won't be used by the UTF-8
	// IDNs.)
	//
	std::vector<condor_sockaddr> ret;
	for( int i = 0; i < hostname.length(); ++i ) {
		if( isalnum( hostname[i] ) || hostname[i] == '-' ) { continue; }
		if( hostname[i] == '.' && i + 1 < hostname.length()
			&& hostname[i+1] != '.' ) { continue; }

		dprintf( D_HOSTNAME, "resolve_hostname_raw(): argument '%s' is not a valid DNS name, returning no addresses.\n", hostname.c_str() );
		return ret;
	}

	addrinfo_iterator ai;
	int res  = ipv6_getaddrinfo(hostname.Value(), NULL, ai);
	if (res) {
		dprintf(D_HOSTNAME, "ipv6_getaddrinfo() could not look up %s: %s (%d)\n", 
			hostname.Value(), gai_strerror(res), res);
		return ret;
	}

	// To eliminate duplicate address, here we use std::set.
	// we also want to maintain the order given by getaddrinfo.
	std::set<condor_sockaddr> s;
	while (addrinfo* info = ai.next()) {
		condor_sockaddr addr(info->ai_addr);
		if (s.find(addr) == s.end()) {
			ret.push_back(addr);
			s.insert(addr);
		}
	}
	return ret;
}

MyString convert_ipaddr_to_hostname(const condor_sockaddr& addr)
{
	MyString ret;
	MyString default_domain;
	if (!param(default_domain, "DEFAULT_DOMAIN_NAME")) {
		dprintf(D_HOSTNAME,
				"NO_DNS: DEFAULT_DOMAIN_NAME must be defined in your "
				"top-level config file\n");
		return ret;
	}

	ret = addr.to_ip_string();
	for (int i = 0; i < ret.Length(); ++i) {
		if (ret[i] == '.' || ret[i] == ':')
			ret.setChar(i, '-');
	}
	ret += ".";
	ret += default_domain;

	// Hostnames can't begin with -, as per RFC 1123
	// ipv6 zero-compression could cause this, esp. for the loopback addr
	if (ret[0] == '-') {
		ret = "0" + ret;
	}

	return ret;
}

// Upon failure, return condor_sockaddr::null
condor_sockaddr convert_hostname_to_ipaddr(const MyString& fullname)
{
	MyString hostname;
	MyString default_domain;
	bool truncated = false;
	if (param(default_domain, "DEFAULT_DOMAIN_NAME")) {
		MyString dotted_domain = ".";
		dotted_domain += default_domain;
		int pos = fullname.find(dotted_domain.Value());
		if (pos != -1) {
			truncated = true;
			hostname = fullname.Substr(0, pos - 1);
		}
	}
	if (!truncated)
		hostname = fullname;

	// detects if hostname is IPv6
	//
	// hostname is NODNS coded address
	//
	// for example,
	// it could be 127-0-0-1 (127.0.0.1) as IPv4 address
	// it could be fe80-3577--1234 ( fe80:3577::1234) as IPv6 address
	//
	// it is IPv6 address
	// 1) if there are 7 '-'
	// 2) if there are '--' which means compaction of zeroes in IPv6 adress

	char target_char;
	bool ipv6 = false;
	if (hostname.find("--") != -1)
		ipv6 = true;
	else {
		int dash_count = 0;
		for (int i = 0; i < hostname.Length(); ++i)
			if (hostname[i] == '-')
				++dash_count;

		if (dash_count == 7)
			ipv6 = true;
	}

	if (ipv6)
		target_char = ':';
	else
		target_char ='.';
		// converts hostname to IP address string
	for (int i = 0; i < hostname.Length(); ++i) {
		if (hostname[i] == '-')
			hostname.setChar(i, target_char);
	}

	condor_sockaddr ret;
	ret.from_ip_string(hostname);
	return ret;
}
