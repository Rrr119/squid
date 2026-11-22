/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"

#if USE_AUTH

#include "acl/FilledChecklist.h"
#include "auth/Acl.h"
#include "auth/Gadgets.h"
#include "auth/UserDomainAcl.h"
#include "auth/UserRequest.h"
#include "anyp/Uri.h"
#include "ConfigParser.h"
#include "HttpRequest.h"

#include <algorithm>
#include <cstring>
#include <string>

UserDomainAclData::UserDomainAclData():
    caseSensitivity_("-i", "+i"),
    lineOptions_{&caseSensitivity_}
{
    caseSensitivity_.linkWith(&caseInsensitive_);
}

const Acl::Options &
UserDomainAclData::lineOptions()
{
    return lineOptions_;
}

void
UserDomainAclData::parse()
{
    // Acl::Node::parseFlags() normally consumes this option before parse() is
    // called. Supporting it here as well keeps the data object directly usable
    // by tests and by future configuration compilers.
    if (const char *first = ConfigParser::PeekAtToken()) {
        if (strcmp(first, "-i") == 0) {
            (void)ConfigParser::NextToken();
            caseInsensitive_.configured = true;
            caseInsensitive_.disabled = false;
            caseInsensitive_.value = true;
        } else if (strcmp(first, "+i") == 0) {
            (void)ConfigParser::NextToken();
            caseInsensitive_.configured = true;
            caseInsensitive_.disabled = true;
            caseInsensitive_.value = false;
        }
    }

    const bool caseInsensitive = bool(caseInsensitive_);

    while (const char *rawUser = ConfigParser::strtokFile()) {
        const char *rawDomain = ConfigParser::strtokFile();
        if (!rawDomain) {
            debugs(28, DBG_CRITICAL, "ERROR: user_domain ACL requires user/domain pairs; missing domain for '" << rawUser << "'");
            invalid_ = true;
            break;
        }

        SBuf user(rawUser);
        SBuf domain(rawDomain);

        if (user.isEmpty() || domain.isEmpty()) {
            debugs(28, DBG_CRITICAL, "ERROR: user_domain ACL does not accept empty users or domains");
            invalid_ = true;
            break;
        }

        domain.toLower();
        rules_.push_back(Rule{user, domain, caseInsensitive});
    }

    compiled_ = false;
}

void
UserDomainAclData::prepareForUse()
{
    if (compiled_)
        return;

    for (auto &rule: rules_) {
        if (rule.caseInsensitive)
            rule.user.toLower();
    }

    // Normalizing during compilation keeps the hot matching path free from
    // per-request case conversions. Stable sorting also makes diagnostics and
    // duplicate rules deterministic without changing rule semantics.
    std::stable_sort(rules_.begin(), rules_.end(), [](const Rule &a, const Rule &b) {
        return a.user.cmp(b.user) < 0;
    });

    compiled_ = true;
}

bool
UserDomainAclData::userMatches(const Rule &rule, const char *user)
{
    if (rule.user.cmp("ANY") == 0)
        return true;

    const auto configuredUser = rule.user.toStdString();
    if (rule.caseInsensitive)
        return strcasecmp(user, configuredUser.c_str()) == 0;

    return strcmp(user, configuredUser.c_str()) == 0;
}

bool
UserDomainAclData::domainMatches(const Rule &rule, const char *host)
{
    // Domain values are lower-cased during parsing.
    if (rule.domain.cmp("any") == 0)
        return true;

    const auto configuredDomain = rule.domain.toStdString();
    return matchDomainName(host, configuredDomain.c_str()) == 0;
}

bool
UserDomainAclData::match(const char *user, const char *host) const
{
    if (!compiled_ || !user || !host || !*user || !*host)
        return false;

    for (const auto &rule: rules_) {
        if (userMatches(rule, user) && domainMatches(rule, host))
            return true;
    }

    return false;
}

SBufList
UserDomainAclData::dump() const
{
    SBufList result;
    for (const auto &rule: rules_) {
        result.push_back(rule.user);
        result.push_back(rule.domain);
    }
    return result;
}

bool
UserDomainAclData::empty() const
{
    return rules_.empty();
}

bool
UserDomainAclData::valid() const
{
    return !invalid_;
}

/* UserDomainAcl */

UserDomainAcl::UserDomainAcl(char const *typeName):
    type_(typeName)
{
}

char const *
UserDomainAcl::typeString() const
{
    return type_;
}

const Acl::Options &
UserDomainAcl::lineOptions()
{
    return data_.lineOptions();
}

void
UserDomainAcl::parse()
{
    data_.parse();
}

void
UserDomainAcl::prepareForUse()
{
    data_.prepareForUse();
}

int
UserDomainAcl::match(ACLChecklist * const checklist)
{
    const auto answer = AuthenticateAcl(checklist, *this);

    switch (answer) {
    case ACCESS_ALLOWED: {
        const auto filled = Filled(checklist);
        const char *user = filled->auth_user_request ? filled->auth_user_request->username() : nullptr;
        const bool matched = user && data_.match(user, filled->request->url.host());
        filled->auth_user_request = nullptr;
        return matched ? 1 : 0;
    }

    case ACCESS_DENIED:
        return 0;

    case ACCESS_DUNNO:
    case ACCESS_AUTH_REQUIRED:
    default:
        if (checklist->keepMatching())
            checklist->markFinished(answer, "AuthenticateAcl exception");
        return -1;
    }
}

SBufList
UserDomainAcl::dump() const
{
    return data_.dump();
}

bool
UserDomainAcl::empty() const
{
    return data_.empty();
}

bool
UserDomainAcl::valid() const
{
    if (!data_.valid())
        return false;

    if (authenticateSchemeCount() == 0) {
        debugs(28, DBG_CRITICAL, "ERROR: Cannot use user_domain ACL because no authentication schemes were compiled.");
        return false;
    }

    if (authenticateActiveSchemeCount() == 0) {
        debugs(28, DBG_CRITICAL, "ERROR: Cannot use user_domain ACL because no authentication schemes are fully configured.");
        return false;
    }

    return true;
}

#endif /* USE_AUTH */
