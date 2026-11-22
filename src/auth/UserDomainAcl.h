/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_USERDOMAINACL_H
#define SQUID_SRC_AUTH_USERDOMAINACL_H

#if USE_AUTH

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Options.h"
#include "sbuf/List.h"

#include <vector>

/// Parsed and compiled user-and-destination-domain ACL rules.
///
/// Each rule pairs one authenticated proxy user with one destination domain.
/// A rule matches only when both halves match the same request. Domain values
/// use the same matching syntax as the dstdomain ACL.
class UserDomainAclData
{
public:
    UserDomainAclData();

    /// parses "user domain [user domain ...]" pairs from the current line
    void parse();

    /// prepares parsed rules for fast runtime matching
    void prepareForUse();

    /// whether the authenticated user and destination host match one rule
    bool match(const char *user, const char *host) const;

    SBufList dump() const;
    bool empty() const;
    bool valid() const;

    /// number of compiled rules (primarily useful for diagnostics/tests)
    size_t ruleCount() const { return rules_.size(); }

    const Acl::Options &lineOptions();

private:
    struct Rule {
        SBuf user;
        SBuf domain;
        bool caseInsensitive = false;
    };

    static bool userMatches(const Rule &rule, const char *user);
    static bool domainMatches(const Rule &rule, const char *host);

    Acl::BooleanOption caseSensitivity_;
    Acl::BooleanOptionValue caseInsensitive_;
    Acl::Options lineOptions_;
    std::vector<Rule> rules_;
    bool invalid_ = false;
    bool compiled_ = false;
};

/// a "user_domain" ACL
class UserDomainAcl: public Acl::Node
{
    MEMPROXY_CLASS(UserDomainAcl);

public:
    explicit UserDomainAcl(char const *typeName);

    /* Acl::Node API */
    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *) override;
    SBufList dump() const override;
    bool empty() const override;
    bool valid() const override;
    bool isProxyAuth() const override { return true; }
    bool requiresRequest() const override { return true; }
    void prepareForUse() override;

private:
    const Acl::Options &lineOptions() override;

    UserDomainAclData data_;
    char const *type_;
};

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_USERDOMAINACL_H */
